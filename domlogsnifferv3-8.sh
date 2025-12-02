#!/bin/bash

# Robbie Powell's Domlog Sniffer
# Version: 3.3 (In-memory + cleaned UI + regex fix)
# Description: A script to analyse Apache domlogs for traffic patterns, bot detection, and abuse.
# Author: Robbie Powell

VERSION="3.3"

show_help() {
    echo "============================================="
    echo "             Domlog Sniffer"
    echo "============================================="
    echo "Author: Robbie Powell"
    echo "Version: $VERSION"
    echo
    echo "Description:"
    echo "  This script analyses Apache domlogs for various traffic patterns:"
    echo "  Top asset hits"
    echo "  Bot traffic"
    echo "  WordPress abuse indicators"
    echo "  Request breakdowns by IP and User-Agent"
    echo
    echo "Usage:"
    echo "  ./domlog_sniffer.sh [OPTIONS]"
    echo
    echo "Options:"
    echo "  -v, --version   Show the script version and exit."
    echo "  -h, --help      Show this help message and exit."
    echo
}

# Flag handling
if [[ "$1" == "-v" || "$1" == "--version" ]]; then
    echo "Domlog Sniffer by Robbie Powell, Version: $VERSION"
    exit 0
elif [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Colours
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
BLUE="\e[34m"
MAGENTA="\e[35m"
BOLD="\e[1m"
RESET="\e[0m"

clear

# Clean title block
echo -e "${GREEN}${BOLD}=============================================${RESET}"
echo -e "${BLUE}${BOLD}Domlog Sniffer${RESET}"
echo -e "${CYAN}${BOLD}Version ${VERSION}${RESET}"
echo -e "${GREEN}${BOLD}=============================================${RESET}"
echo -e "${YELLOW}${BOLD}Apache domlog analysis tool${RESET}"
echo -e "${GREEN}${BOLD}=============================================${RESET}"
echo

# Domain input
read -p "$(echo -e "${MAGENTA}${BOLD}Enter the domain to analyse: ${RESET}")" domain

log_locations=(
    "/usr/local/apache/domlogs/$domain"
    "/usr/local/apache/domlogs/$domain-ssl_log"
    "/usr/local/apache/domlogs/*/$domain"
    "/usr/local/apache/domlogs/*/$domain-ssl_log"
)

log_files=()

for location in "${log_locations[@]}"; do
    for log_file in $location; do
        [[ -f "$log_file" && -s "$log_file" ]] && log_files+=("$log_file")
    done
done

if [[ ${#log_files[@]} -eq 0 ]]; then
    echo -e "${RED}${BOLD}No log files found for '${domain}'.${RESET}"
    exit 1
fi

echo -e "${CYAN}${BOLD}Loading logs into memory...${RESET}"

declare -a log_buffer
while IFS= read -r line; do
    log_buffer+=("$line")
done < <(cat "${log_files[@]}")

echo -e "${GREEN}${BOLD}Loaded ${#log_buffer[@]} log lines into memory.${RESET}"

earliest_entry=$(printf "%s\n" "${log_buffer[@]}" | awk '{print $4}' | sed 's/\[//' | sort | head -n 1)
[[ -z "$earliest_entry" ]] && earliest_entry="Unknown"

echo -e "${MAGENTA}${BOLD}Earliest Log Entry:${RESET} $earliest_entry"

# Requests by hour
echo -e "\n${YELLOW}${BOLD}-----------------------------------${RESET}"
echo -e "${CYAN}${BOLD}Requests Breakdown by Hour:${RESET}"
echo -e "${YELLOW}${BOLD}-----------------------------------${RESET}"

printf "%s\n" "${log_buffer[@]}" \
    | awk '{print substr($4, 2, 14)}' \
    | awk -F':' '{print $1":"$2":00"}' \
    | sort | uniq -c | column -t

# Timeframe selection
echo -e "\n${YELLOW}${BOLD}-----------------------------------${RESET}"
echo -e "${CYAN}${BOLD}Timeframe Options:${RESET}"
echo -e "${YELLOW}${BOLD}-----------------------------------${RESET}"
echo "1) Last X minutes"
echo "2) Specific time range"

read -p "$(echo -e "${MAGENTA}${BOLD}Select an option (1 or 2): ${RESET}")" option

if [[ "$option" -eq 1 ]]; then
    read -p "$(echo -e "${MAGENTA}${BOLD}Enter timeframe in minutes: ${RESET}")" timeframe
    start_time=$(date -d "$timeframe min ago" +"%d/%b/%Y:%H:%M:%S")
    end_time=$(date +"%d/%b/%Y:%H:%M:%S")
elif [[ "$option" -eq 2 ]]; then
    read -p "$(echo -e "${CYAN}${BOLD}Enter start time (DD/Mon/YYYY:HH:MM:SS): ${RESET}")" start_time
    read -p "$(echo -e "${CYAN}${BOLD}Enter end time (DD/Mon/YYYY:HH:MM:SS): ${RESET}")" end_time
else
    echo -e "${RED}${BOLD}Invalid option. Exiting.${RESET}"
    exit 1
fi

# Filter logs by timeframe
filter_logs() {
    printf "%s\n" "${log_buffer[@]}" | awk -v start="$start_time" -v end="$end_time" '$4 >= "["start && $4 <= "["end'
}

# Section print helpers
print_header() {
    echo -e "\n${YELLOW}${BOLD}-----------------------------------${RESET}"
    echo -e "${CYAN}${BOLD}$1${RESET}"
    echo -e "${YELLOW}${BOLD}-----------------------------------${RESET}"
}

print_section() {
    local header=$1
    local cmd=$2
    print_header "$header"
    output=$(filter_logs | eval "$cmd")
    [[ -z "$output" ]] && echo -e "${RED}${BOLD}No matches found.${RESET}" || echo "$output"
}

# Top Asset Hits
print_section "Top Asset Hits" \
"awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -30"

# Bot Traffic (clean + fixed quoting)

print_header "Checking for Bot Traffic"
filter_logs \
  | grep -Ei 'bot|spider|crawl|crawler|crawling|ahrefs|mj12|semrush|dotbot|gptbot|oai|openai|searchbot|bingpreview|facebookexternalhit|yandex|duckduck|baidu|sogou|meta|censys|zoombot|petalbot|dataforseo|coccoc' \
  | awk '{print $6, $14}' \
  | sort \
  | uniq -c \
  | sort -n \
  | tail -25

# WordPress abuse
print_section "Checking for WordPress Abuse" \
"grep -Ei '(wp-login.php|xmlrpc.php|wp-admin)' | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -30"

# Top IPs
print_header "Top Hits Sorted by IP Address"
filter_logs \
| awk '{print $1}' \
| sort | uniq -c | sort -nr | head -30 \
| while read -r count ip; do
    country=$(geoiplookup "$ip" 2>/dev/null | awk -F ': ' '{print $2}')
    # Remove quotes and commas
    country=$(echo "$country" | sed 's/,//g')
    printf "%6s  %-15s  %s\n" "$count" "$ip" "$country"
done

# User agents
print_section "User-Agent Analysis" \
"awk -F'\"' '{print \$6}' | sort | uniq -c | sort -nr | head -30"

# Referrers
print_section "Referrer Analysis" \
"awk '{print \$11}' | sort | uniq -c | sort -nr | head -30"

# Bot Traffic (clean + fixed quoting)

print_header "Checking for Bot Traffic"
filter_logs \
  | grep -Ei 'bot|spider|crawl|crawler|crawling|ahrefs|mj12|semrush|dotbot|gptbot|oai|openai|searchbot|bingpreview|facebookexternalhit|yandex|duckduck|baidu|sogou|meta|censys|zoombot|petalbot|dataforseo|coccoc' \
  | awk '{print $6, $14}' \
  | sort \
  | uniq -c \
  | sort -n \
  | tail -25


# Status code breakdowns
print_section "404 Requests Analysis" \
"grep ' 404 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -30"

print_section "500 Requests Analysis" \
"grep ' 500 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -30"

print_section "403 Requests Analysis" \
"grep ' 403 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -30"

print_section "503 Requests Analysis" \
"grep ' 503 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -30"

echo -e "\n${GREEN}${BOLD}Analysis complete!${RESET}"


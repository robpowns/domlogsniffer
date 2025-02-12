 #!/bin/bash

# Robbie Powell's Domlog Sniffer
# Version: 3.0
# Description: A script to analyse Apache domlogs for traffic patterns, bot detection, and abuse.
# Author: Robbie Powell

VERSION="3.0"

# Function to display the help message
show_help() {
    echo "============================================="
    echo "             Domlog Sniffer"
    echo "============================================="
    echo "Author: Robbie Powell"
    echo "Version: $VERSION"
    echo
    echo "Description:"
    echo "  This script analyses Apache domlogs for various traffic patterns, including:"
    echo "  - Top asset hits"
    echo "  - Bot traffic"
    echo "  - WordPress abuse indicators"
    echo "  - Request breakdowns by IP and User-Agent"
    echo
    echo "Usage:"
    echo "  ./domlog_sniffer.sh [OPTIONS]"
    echo
    echo "Options:"
    echo "  -v, --version     Show the script version and exit."
    echo "  -h, --help        Show this help message and exit."
    echo
    echo "Example:"
    echo "  ./domlog_sniffer.sh"
    echo
}

# Check for flags
if [[ "$1" == "-v" || "$1" == "--version" ]]; then
    echo "Domlog Sniffer by Robbie Powell, Version: $VERSION"
    exit 0
elif [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Colour definitions for readability
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
BLUE="\e[34m"
MAGENTA="\e[35m"
BOLD="\e[1m"
RESET="\e[0m"

clear

# Sweet Title Section
echo -e "${BLUE}${BOLD}"
echo "  DDDD    OOO   M   M  L        OOO   GGGG     SSSS  N   N  III FFFFF  FFFFF  EEEEE  RRRRR"
echo "  D   D  O   O  MM MM  L       O   O  G        S     NN  N   I  F      F      E      R   R"
echo "  D   D  O   O  M M M  L       O   O  G  GG     SSS  N N N   I  FFFF   FFFF   EEEE   RRRRR"
echo "  D   D  O   O  M   M  L       O   O  G   G       S  N  NN   I  F      F      E      R  R"
echo "  DDDD    OOO   M   M  LLLLL    OOO   GGGGG    SSSS  N   N  III F      F      EEEEE  R   R"
echo -e "${RESET}"
echo -e "${GREEN}${BOLD}=============================================${RESET}"
echo -e "${CYAN}${BOLD}             Domlog Sniffer v$VERSION${RESET}"
echo -e "${GREEN}${BOLD}=============================================${RESET}"
echo -e "${YELLOW}${BOLD}  Description: Apache domlog analysis tool${RESET}"
echo -e "${GREEN}${BOLD}=============================================${RESET}"
echo

# Prompt for domain
read -p "$(echo -e "${MAGENTA}${BOLD}Enter the domain to analyse: ${RESET}")" domain

# Define log file locations to check
log_locations=(
    "/usr/local/apache/domlogs/$domain"
    "/usr/local/apache/domlogs/$domain-ssl_log"
    "/usr/local/apache/domlogs/*/$domain"
    "/usr/local/apache/domlogs/*/$domain-ssl_log"
)

# Find all log files matching the domain pattern
log_files=()
for location in "${log_locations[@]}"; do
    for log_file in $location; do
        if [[ -f "$log_file" && -s "$log_file" ]]; then
            log_files+=("$log_file")
        fi
    done
done

# Check if any log files were found
if [[ ${#log_files[@]} -eq 0 ]]; then
    echo -e "${RED}${BOLD}No log files found for the domain '${domain}'.${RESET}"
    exit 1
fi

# Combine all non-empty log files into a single temporary file for analysis
temp_log=$(mktemp)
for log_file in "${log_files[@]}"; do
    echo -e "${CYAN}${BOLD}Adding log file: $log_file${RESET}"
    cat "$log_file" >> "$temp_log"
done

# Check for earliest log entry
earliest_entry=$(awk '{print $4}' "$temp_log" 2>/dev/null | sed 's/\[//' | sort | head -n 1)
if [[ -z "$earliest_entry" ]]; then
    echo -e "${YELLOW}${BOLD}Warning: Unable to parse timestamps, but log file has content. Proceeding with analysis.${RESET}"
    earliest_entry="Unknown"
fi

echo -e "${MAGENTA}${BOLD}Earliest Log Entry:${RESET} $earliest_entry"

# Requests breakdown by hour sorts into highest to lowest 
echo -e "\n${YELLOW}${BOLD}-----------------------------------${RESET}"
echo -e "${CYAN}${BOLD}Requests Breakdown by Hour:${RESET}"
echo -e "${YELLOW}${BOLD}-----------------------------------${RESET}"
awk '{print substr($4, 2, 14)}' "$temp_log" 2>/dev/null | awk -F':' '{print $1":"$2":00"}' | sort | uniq -c | sort -nr | column -t

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
    echo -e "${MAGENTA}${BOLD}Timeframe:${RESET} $start_time to $end_time"
elif [[ "$option" -eq 2 ]]; then
    read -p "$(echo -e "${CYAN}${BOLD}Enter start time (DD/Mon/YYYY:HH:MM:SS): ${RESET}")" start_time
    read -p "$(echo -e "${CYAN}${BOLD}Enter end time (DD/Mon/YYYY:HH:MM:SS): ${RESET}")" end_time
    echo -e "${CYAN}${BOLD}Timeframe:${RESET} $start_time to $end_time"
else
    echo -e "${RED}${BOLD}Invalid option. Exiting.${RESET}"
    rm -f "$temp_log"
    exit 1
fi

# Define the awk filter for time range
awk_filter='$4 >= "["start && $4 <= "["end'

# Function to print section headers
print_header() {
    echo -e "\n${YELLOW}${BOLD}-----------------------------------${RESET}"
    echo -e "${CYAN}${BOLD}$1${RESET}"
    echo -e "${YELLOW}${BOLD}-----------------------------------${RESET}"
}

# Function to check if output is empty
print_section() {
    local header=$1
    local command=$2
    print_header "$header"
    output=$(eval "$command")
    if [[ -z "$output" ]]; then
        echo -e "${RED}${BOLD}No matches found.${RESET}"
    else
        echo "$output"
    fi
}

# Top Asset Hits (Top 30)
print_section "Top Asset Hits" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -30"

# Bot Traffic (Top 30)
print_section "Checking for Bot Traffic" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | grep -Ei \"(bot|crawler|spider|googlebot|bingbot|yandexbot)\" | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -30"

# WordPress Abuse (Top 30)
print_section "Checking for WordPress Abuse" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | grep -Ei \"(wp-login.php|xmlrpc.php|wp-admin)\" | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -30"

# Top Hits by IP Address (Top 30)
print_header "Top Hits Sorted by IP Address"
awk -v start="$start_time" -v end="$end_time" '$4 >= "["start && $4 <= "["end' "$temp_log" | awk '{print $1}' | sort | uniq -c | sort -nr | head -30 | while read -r count ip; do
    country=$(geoiplookup "$ip" 2>/dev/null | awk -F ": " '{print $2}')
    printf "%7s %15s %s\n" "$count" "$ip" "$country"
done

# User-Agent Analysis (Top 30)
print_section "User-Agent Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | awk -F'\"' '{print \$6}' | sort | uniq -c | sort -nr | head -30"

# Referrer Analysis (Top 30)
print_section "Referrer Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | awk '{print \$11}' | sort | uniq -c | sort -nr | head -30"

# 404 Requests Analysis (Top 30)
print_section "404 Requests Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | grep ' 404 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -30"

# 500 Requests Analysis (Top 30)
print_section "500 Requests Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | grep ' 500 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -30"

# 403 Requests Analysis (Top 30)
print_section "403 Requests Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | grep ' 403 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -30"

# 503 Requests Analysis (Top 30)
print_section "503 Requests Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' \"$temp_log\" | grep ' 503 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -30"

# Clean up temporary file
rm -f "$temp_log"

# End of the script
echo -e "\n${GREEN}${BOLD}Analysis complete!${RESET}"

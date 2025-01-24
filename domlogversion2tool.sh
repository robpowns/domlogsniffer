#!/bin/bash

# ================================================
#  Domlog Sniffer - A log analysis tool version 2 
#  
#  This script analyses Apache log files for a 
#  specified domain and provides insights such as:
#  - Top asset hits
#  - Bot traffic detection
#  - WordPress abuse detection
#  - Top hits sorted by IP
#  - User-Agent and Referrer analysis
#  - 404, 500, 403, 503 error request analysis
#  - Requests breakdown by hour
#
#  Created by: Robbie Powell
# ================================================

# Colour definitions for readability
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

clear

# Script header
echo -e "${GREEN}=============================================${RESET}"
echo -e "               ${CYAN}Domlog Sniffer${RESET}"
echo -e "${GREEN}=============================================${RESET}"

# Prompt for domain
read -p "Enter the domain to analyse: " domain

# Check for earliest log entry
earliest_entry=$(awk '{print $4}' /usr/local/apache/domlogs/$domain 2>/dev/null | sed 's/\[//' | sort | head -n 1)
if [[ -z "$earliest_entry" ]]; then
    echo -e "${RED}No log entries found for the domain '${domain}'.${RESET}"
    exit 1
fi

echo -e "${CYAN}Earliest Log Entry:${RESET} $earliest_entry"

# Requests breakdown by hour sorts into highest to lowest 
echo -e "\n${YELLOW}-----------------------------------${RESET}"
echo -e "${CYAN}Requests Breakdown by Hour:${RESET}"
echo -e "${YELLOW}-----------------------------------${RESET}"
awk '{print substr($4, 2, 14)}' /usr/local/apache/domlogs/$domain 2>/dev/null | awk -F':' '{print $1":"$2":00"}' | sort | uniq -c | sort -nr | column -t

# Timeframe selection
echo -e "\n${YELLOW}-----------------------------------${RESET}"
echo -e "${CYAN}Timeframe Options:${RESET}"
echo -e "${YELLOW}-----------------------------------${RESET}"
echo "1) Last X minutes"
echo "2) Specific time range"
read -p "Select an option (1 or 2): " option

if [[ "$option" -eq 1 ]]; then
    read -p "Enter timeframe in minutes: " timeframe
    start_time=$(date -d "$timeframe min ago" +"%d/%b/%Y:%H:%M:%S")
    end_time=$(date +"%d/%b/%Y:%H:%M:%S")
    echo -e "${CYAN}Timeframe:${RESET} $start_time to $end_time"
elif [[ "$option" -eq 2 ]]; then
    read -p "Enter start time (DD/Mon/YYYY:HH:MM:SS): " start_time
    read -p "Enter end time (DD/Mon/YYYY:HH:MM:SS): " end_time
    echo -e "${CYAN}Timeframe:${RESET} $start_time to $end_time"
else
    echo -e "${RED}Invalid option. Exiting.${RESET}"
    exit 1
fi

# Define the awk filter for time range (needed for checking if time falls inside time in log) 
awk_filter='$4 >= "["start && $4 <= "["end'

# Function to print section headers
print_header() {
    echo -e "\n${YELLOW}-----------------------------------${RESET}"
    echo -e "${CYAN}$1${RESET}"
    echo -e "${YELLOW}-----------------------------------${RESET}"
}

# Function to check if output is empty
print_section() {
    local header=$1
    local command=$2
    print_header "$header"
    output=$(eval "$command")
    if [[ -z "$output" ]]; then
        echo -e "${RED}No matches found.${RESET}"
    else
        echo "$output"
    fi
}

# Top Asset Hits
print_section "Top Asset Hits" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr | head -10"

# Bot Traffic
print_section "Checking for Bot Traffic" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | grep -Ei \"(bot|crawler|spider|googlebot|bingbot|yandexbot)\" | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr"

# WordPress Abuse
print_section "Checking for WordPress Abuse" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | grep -Ei \"(wp-login.php|xmlrpc.php|wp-admin)\" | awk '{print \$1, \$6, \$7}' | sort | uniq -c | sort -nr"

# Top Hits by IP Address
print_header "Top Hits Sorted by IP Address"
awk -v start="$start_time" -v end="$end_time" '$4 >= "["start && $4 <= "["end' /usr/local/apache/domlogs/$domain | awk '{print $1}' | sort | uniq -c | sort -nr | while read -r count ip; do
    country=$(geoiplookup "$ip" | awk -F ": " '{print $2}')
    printf "%7s %15s %s\n" "$count" "$ip" "$country"
done

# User-Agent Analysis
print_section "User-Agent Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | awk -F'\"' '{print \$6}' | sort | uniq -c | sort -nr | head -10"

# Referrer Analysis
print_section "Referrer Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | awk '{print \$11}' | sort | uniq -c | sort -nr | head -10"

# 404 Requests Analysis
print_section "404 Requests Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | grep ' 404 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -10"

# 500 Requests Analysis
print_section "500 Requests Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | grep ' 500 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -10"

# 403 Requests Analysis
print_section "403 Requests Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | grep ' 403 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -10"

# 503 Requests Analysis
print_section "503 Requests Analysis" \
    "awk -v start=\"$start_time\" -v end=\"$end_time\" '$awk_filter' /usr/local/apache/domlogs/$domain | grep ' 503 ' | awk '{print \$1, \$7}' | sort | uniq -c | sort -nr | head -10"

# End of the script
echo -e "\n${GREEN}Analysis complete!${RESET}"


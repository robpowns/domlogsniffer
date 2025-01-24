#!/bin/bash

clear

echo "============================================="
echo -e "             \e[32mDomlog Sniffer\e[0m"
echo "============================================="

echo -e "\e[32mOptions\e[0m"
# Domain to be used for the report
read -p 'Domain: ' domain

# Extract and display the earliest entry timestamp for the given domain
earliest_entry=$(awk '{print $4}' /usr/local/apache/domlogs/$domain | sed 's/\[//' | sort | head -n 1)
if [[ -n "$earliest_entry" ]]; then
    echo -e "\e[32mEarliest Log Entry:\e[0m $earliest_entry"
else
    echo -e "\e[31mNo log entries found for the domain $domain\e[0m"
    exit 1
fi

echo
echo "=========================================================================================="
echo -e "\e[32mRequests Breakdown by Hour:\e[0m"
echo "=========================================================================================="

# Searching for log entries grouped by hour for the entire domain log
output=$(awk '{print substr($4, 2, 14)}' /usr/local/apache/domlogs/$domain | awk -F':' '{print $1":"$2":00"}' | sort | uniq -c | sort -nr)
if [[ -n "$output" ]]; then
    echo "$output"
else
    echo -e "\e[31mNo requests found in the log file.\e[0m"
fi

echo
echo "=========================================================================================="
echo -e "\e[32mTimeframe Options\e[0m"
echo "=========================================================================================="

# Prompt user to choose input method
echo "Choose the input method for the timeframe:"
echo "1) Timeframe in minutes"
echo "2) Specific time/date range"
read -p "Enter your choice (1 or 2): " choice

if [[ "$choice" -eq 1 ]]; then
    # Timeframe in minutes
    read -p 'Timeframe (In minutes): ' timeframe
    start_time=$(date -d "$timeframe min ago" +"%d/%b/%Y:%H:%M:%S")
    echo -e "\e[32mRange:\e[0m"
    echo -e "           Start: $(date -d "$timeframe min ago")"
    echo -e "           End:   $(date)"
elif [[ "$choice" -eq 2 ]]; then
    # Specific time/date range
    read -p 'Start time (format: DD/Mon/YYYY:HH:MM:SS): ' start_time
    read -p 'End time (format: DD/Mon/YYYY:HH:MM:SS): ' end_time
    echo -e "\e[32mRange:\e[0m"
    echo -e "           Start: $start_time"
    echo -e "           End:   $end_time"
else
    echo -e "\e[31mInvalid choice. Exiting.\e[0m"
    exit 1
fi

echo ""

# Define the `awk` command for filtering based on the chosen input
if [[ "$choice" -eq 1 ]]; then
    awk_filter='$4 > "["start'
else
    awk_filter='$4 > "["start && $4 < "["end'
fi

# Function to handle output checks and print a message if no matches are found
check_output() {
    if [[ -z "$1" ]]; then
        echo -e "\e[31mNo matches found.\e[0m"
    else
        echo "$1"
    fi
}

# Top Asset Hits
echo "=========================================================================================="
echo -e  "\e[32mTop Asset Hits:\e[0m"
echo "=========================================================================================="
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | awk '{print $1,$6,$7}' | sort | uniq -c | tail -15 | sort -nr)
check_output "$output"

# Bot Traffic
echo
echo "=========================================================================================="
echo -e "\e[32mChecking for Bot Traffic:\e[0m"
echo "=========================================================================================="

# Pattern for common bot user-agents
bot_patterns="(bot|crawler|spider|googlebot|bingbot|yandexbot)"

# Searching for bot traffic in the logs within the specified timeframe and domain
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | grep -Ei "$bot_patterns" | awk '{print $1,$6,$7}' | sort | uniq -c | sort -n)
check_output "$output"

# WordPress Abuse
echo
echo "=========================================================================================="
echo -e "\e[32mChecking for WordPress Abuse:\e[0m"
echo "=========================================================================================="

# Patterns for common WordPress abuse indicators
wordpress_abuse_patterns="(wp-login.php|xmlrpc.php|wp-admin)"

# Searching for WordPress abuse in the logs within the specified timeframe and domain
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | grep -Ei "$wordpress_abuse_patterns" | awk '{print $1,$6,$7}' | sort | uniq -c | sort -n)
check_output "$output"

# Top Hits Sorted by IP Address
echo ""
echo "=========================================================================================="
echo -e "\e[32mChecking for Top Hits Sorted by IP Address:\e[0m"
echo "=========================================================================================="

# Searching for log entries within the specified timeframe and domain
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | awk '{print $1}' | sort | uniq -c | sort -nr | while read -r count ip; do
    country=$(geoiplookup "$ip" | awk -F ": " '{print $2}')
    printf "%7s %15s %s\n" "$count" "$ip" "$country"
done)
check_output "$output"

# User-Agent Analysis
echo
echo "=========================================================================================="
echo -e "\e[32mUser-Agent Analysis:\e[0m"
echo "=========================================================================================="
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | awk -F'"' '{print $6}' | sort | uniq -c | sort -nr)
check_output "$output"

# Referrer Analysis
echo
echo "=========================================================================================="
echo -e "\e[32mReferrer Analysis:\e[0m"
echo "=========================================================================================="
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | awk '{print $11}' | sort | uniq -c | sort -nr)
check_output "$output"

# 404 Requests Analysis
echo ""
echo "=========================================================================================="
echo -e "\e[32m404 Requests Analysis:\e[0m"
echo "=========================================================================================="
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | grep ' 404 ' | awk '{print $1 $7}' | sort | uniq -c | sort -nr)
check_output "$output"

# 500 Requests Analysis
echo ""
echo "=========================================================================================="
echo -e "\e[32m500 Requests Analysis:\e[0m"
echo "=========================================================================================="
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | grep ' 500 ' | awk '{print $1 $7}' | sort | uniq -c | sort -nr)
check_output "$output"

# 403 Requests Analysis
echo ""
echo "=========================================================================================="
echo -e "\e[32m403 Requests Analysis:\e[0m"
echo "=========================================================================================="
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | grep ' 403 ' | awk '{print $1 $7}' | sort | uniq -c | sort -nr)
check_output "$output"

# 503 Requests Analysis
echo ""
echo "=========================================================================================="
echo -e "\e[32m503 Requests Analysis:\e[0m"
echo "=========================================================================================="
output=$(awk -v start="$start_time" -v end="$end_time" "$awk_filter" /usr/local/apache/domlogs/$domain | grep ' 503 ' | awk '{print $1 $7}' | sort | uniq -c | sort -nr)
check_output "$output"

echo ""
echo "Analysis complete."


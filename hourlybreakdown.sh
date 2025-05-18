#!/bin/bash

if [[ -z "$1" ]]; then
  echo "Usage: $0 domain_name"
  exit 1
fi

DOMAIN=$1

LOG_FILES=(
  "/usr/local/apache/domlogs/${DOMAIN}"
  "/usr/local/apache/domlogs/${DOMAIN}-ssl_log"
  "/usr/local/apache/domlogs/food/${DOMAIN}"
  "/usr/local/apache/domlogs/food/${DOMAIN}-ssl_log"
)

TMP_LOG="/tmp/${DOMAIN}_combined.log"
> "$TMP_LOG"

for file in "${LOG_FILES[@]}"; do
  if [[ -f "$file" ]]; then
    echo "Adding log file: $file"
    cat "$file" >> "$TMP_LOG"
  fi
done

if [[ ! -s "$TMP_LOG" ]]; then
  echo "No logs found for domain: $DOMAIN"
  exit 1
fi

earliest=$(awk '{
  gsub(/^\[/,"",$4)
  print $4
}' "$TMP_LOG" | sort | head -1)

echo
echo "Earliest Log Entry: $earliest"
echo
echo "----------------------------------------"
echo "  Requests Breakdown by Hour for $DOMAIN"
echo "----------------------------------------"
echo
printf "%6s  %s\n" "Count" "Date & Hour"
echo "----------------------------------------"

awk '{ 
    timestamp=substr($4, 2) 
    split(timestamp, a, ":")
    datehour=a[1]":"a[2]
    counts[datehour]++
} 
END { 
    PROCINFO["sorted_in"] = "@ind_str_asc"  # sort keys ascending by string
    for (key in counts) printf "%6d  %s:00\n", counts[key], key
}' "$TMP_LOG"

rm "$TMP_LOG"


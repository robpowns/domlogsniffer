#!/usr/bin/env python3
import os
import re
import glob
import gzip
import datetime
from multiprocessing import Pool, cpu_count
from collections import defaultdict, Counter

LOG_DIR = "/usr/local/apache/domlogs"

BANNER = r"""
  DDDD    OOO   M   M  L      OOO   GGGG     SSSS  N   N  III FFFFF  FFFFF  EEEEE  RRRRR
  D   D  O   O  MM MM  L     O   O  G        S     NN  N   I  F      F      E      R   R
  D   D  O   O  M M M  L     O   O  G  GG     SSS  N N N   I  FFFF   FFFF   EEEE   RRRRR
  D   D  O   O  M   M  L     O   O  G   G       S  N  NN   I  F      F      E      R  R
  DDDD    OOO   M   M  LLLLL  OOO   GGGGG    SSSS  N   N  III F      F      EEEEE  R   R
"""

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)] "(?P<method>\S+)? (?P<path>\S+)? \S+" (?P<status>\d{3}) \S+ "(?P<referrer>[^"]*)" "(?P<useragent>[^"]*)"'
)

def parse_line(line):
    match = LOG_PATTERN.match(line)
    if match:
        data = match.groupdict()
        try:
            dt = datetime.datetime.strptime(data['datetime'].split()[0], "%d/%b/%Y:%H:%M:%S")
            data['datetime'] = dt
        except:
            return None
        return data
    return None

def read_log_file(path):
    open_fn = gzip.open if path.endswith('.gz') else open
    try:
        with open_fn(path, 'rt', errors='ignore') as f:
            return f.readlines()
    except:
        return []

def process_file(path):
    results = []
    lines = read_log_file(path)
    for line in lines:
        parsed = parse_line(line)
        if parsed:
            results.append(parsed)
    return results

def group_by_hour(logs, start_time):
    hourly = defaultdict(int)
    for entry in logs:
        if entry['datetime'] >= start_time:
            hour = entry['datetime'].replace(minute=0, second=0, microsecond=0)
            hourly[hour] += 1
    return hourly

def top_counts(logs, key, filter_fn=lambda x: True):
    counter = Counter()
    for entry in logs:
        if filter_fn(entry):
            counter[entry[key]] += 1
    return counter.most_common(30)

def analyze(logs, start_time):
    print("\n-----------------------------------\nRequests Breakdown by Hour\n-----------------------------------")
    for hour, count in sorted(group_by_hour(logs, start_time).items()):
        print(f"{hour}: {count} requests")

    print("\n-----------------------------------\nTop Asset Hits (Top 30)\n-----------------------------------")
    for item, count in top_counts(logs, 'path', lambda x: x['path'].lower().endswith(('.js', '.css', '.jpg', '.png', '.gif'))):
        print(f"{count} {item}")

    print("\n-----------------------------------\nChecking for Bot Traffic (Top 30)\n-----------------------------------")
    for item, count in top_counts(logs, 'useragent', lambda x: 'bot' in x['useragent'].lower()):
        print(f"{count} {item}")

    print("\n-----------------------------------\nChecking for WordPress Abuse (Top 30)\n-----------------------------------")
    for item, count in top_counts(logs, 'path', lambda x: '/wp-' in x['path'].lower()):
        print(f"{count} {item}")

    print("\n-----------------------------------\nTop Hits Sorted by IP Address (Top 30)\n-----------------------------------")
    for ip, count in top_counts(logs, 'ip'):
        print(f"{count} {ip}")

    print("\n-----------------------------------\nUser-Agent Analysis (Top 30)\n-----------------------------------")
    for ua, count in top_counts(logs, 'useragent'):
        print(f"{count} {ua}")

    print("\n-----------------------------------\nReferrer Analysis (Top 30)\n-----------------------------------")
    for ref, count in top_counts(logs, 'referrer', lambda x: x['referrer'] and x['referrer'] != '-'):
        print(f"{count} {ref}")

    for status_code in ['404', '500', '403', '503']:
        print(f"\n-----------------------------------\n{status_code} Requests Analysis (Top 30)\n-----------------------------------")
        for item, count in top_counts(logs, 'path', lambda x: x['status'] == status_code):
            print(f"{count} {item}")

def main():
    print(BANNER)
    print("=============================================")
    print("             Domlog Sniffer v3.0")
    print("=============================================")
    print("  Description: Apache domlog analysis tool")
    print("=============================================")

    domain = input("Enter the domain to analyse: ").strip()
    files = glob.glob(f"{LOG_DIR}/{domain}*") + glob.glob(f"{LOG_DIR}/**/{domain}*", recursive=True)
    if not files:
        print("No log files found.")
        return

    print("Found log files:")
    for f in files:
        print(f" - {f}")

    print("\nTimeframe Options:\n1) Last X minutes\n2) Specific time range")
    choice = input("Select an option (1 or 2): ").strip()

    now = datetime.datetime.now()
    if choice == '1':
        minutes = int(input("Enter timeframe in minutes: "))
        start_time = now - datetime.timedelta(minutes=minutes)
    elif choice == '2':
        from_str = input("Enter start time (YYYY-mm-dd HH:MM): ")
        try:
            start_time = datetime.datetime.strptime(from_str, "%Y-%m-%d %H:%M")
        except:
            print("Invalid date format.")
            return
    else:
        print("Invalid selection.")
        return

    print(f"Timeframe: {start_time} to {now}")

    print("\nProcessing logs with multiprocessing...\n")
    with Pool(processes=cpu_count()) as pool:
        all_logs_nested = pool.map(process_file, files)

    # Flatten the list of lists
    all_logs = [entry for sublist in all_logs_nested for entry in sublist]

    analyze(all_logs, start_time)
    print("\nAnalysis complete!")

if __name__ == "__main__":
    main()


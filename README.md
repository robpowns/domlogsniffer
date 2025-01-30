# domlogsniffer

Domlog Sniffer Documentation
Overview
The Domlog Sniffer is a Bash script designed to analyse domlogs for various traffic patterns, including top asset hits, bot traffic, WordPress abuse , and request breakdowns by IP and User-Agent. It is particularly useful for identifying suspicious activity, understanding traffic patterns, finding website downtime.

Features
- Top Asset Hits: Identifies the most frequently accessed assets (e.g., files, pages) on the domain.
- Bot Traffic Detection: Detects and lists traffic from known bots, crawlers, and spiders.
- WordPress Abuse Detection: Flags requests to common WordPress abuse targets such as wp-login.php, xmlrpc.php, and wp-admin.
- IP Address Analysis: Provides a breakdown of requests by IP address, including geolocation data(using geoiplookup).
- User-Agent Analysis: Lists the most common User-Agents accessing the domain.
- Referrer Analysis: Identifies the top referrers to the domain.
- Error Analysis: Analyses requests resulting in HTTP errors (404, 403, 500, 503).


Options
-v or --version: Display the script version.
-h or --help: Display the help message.

Example:
./domlog_sniffer.sh -h

Work flow.... 
Input Domain: 
The script prompts the user to enter the domain to analyse.

Onced entered...

Does Log File Check: 
It checks for the existence of log entries for the specified domain.
Shows time/date of earliest entry in log
Shows breakdown of request by hours sorted by hour 


Timeframe Selection:
- Last X Minutes: Analyse logs from the last specified number of minutes.
- Specific Time Range: Analyse logs within a custom time range.

Analysis:
The script performs various analyses on the log data, including:
- Top asset hits
- Bot traffic detection
- WordPress abuse detection
- IP address and User-Agent breakdowns geolocations 
- Referrer analysis
- Error analysis (404, 403, 500, 503)

Output: 
Results are displayed in a structured format with colour-coded headers for readability.




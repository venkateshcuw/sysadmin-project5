Project 5 - Read the Traffic

Files
code/baseline_flows.csv - normal traffic + baseline notes in comments
code/window_flows.csv - the 1 hour window we check
code/flow_baseline.py - starter file given, just kept for reference
code/gpu_fabric_check.sh - starter file given, not used here
detect_flows.py - my detector script, this is the main file
findings.txt - output of running detect_flows.py
README.txt - this file
AI_USAGE.txt - how I used AI for this
REPORT.docx - report explaining findings in simple words

How to run
python3 detect_flows.py code/baseline_flows.csv code/window_flows.csv

To save output to a file:
python3 detect_flows.py code/baseline_flows.csv code/window_flows.csv > findings.txt

Findings:
1. beaconing - host 10.20.4.62 talking to 203.0.113.77:8443
2. port_scan - host 10.20.4.77 hitting 6 hosts on ports 22/445/3389
3. exfil - host 10.20.4.45 sending way more bytes than normal to 198.51.100.42

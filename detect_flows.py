import csv
import sys
from datetime import datetime

def read_csv(filename):
    data = []
    file = open(filename)
    reader = csv.reader(file)
    header = next(reader)
    for row in reader:
        if len(row) == 0:
            continue
        if row[0].startswith('#'):
            continue
        d = {}
        d['ts'] = row[0]
        d['src_ip'] = row[1]
        d['dst_ip'] = row[2]
        d['dst_port'] = int(row[3])
        d['proto'] = row[4]
        d['bytes_out'] = int(row[5])
        d['bytes_in'] = int(row[6])
        data.append(d)
    file.close()
    return data

def get_baseline_notes(filename):
    notes = {}
    file = open(filename)
    lines = file.readlines()
    file.close()
    for line in lines:
        if line.startswith('# host'):
            parts = line.split()
            host = parts[2]
            for p in parts:
                if p.startswith('p95_out='):
                    val = p.replace('p95_out=', '')
                    val = val.replace('KB', '')
                    notes[host] = float(val) * 1024
    return notes

baseline_rows = read_csv(sys.argv[1])
window_rows = read_csv(sys.argv[2])
notes = get_baseline_notes(sys.argv[1])

host_bytes = {}
host_dst_ips = {}
host_dst_ports = {}

for row in baseline_rows:
    h = row['src_ip']
    if h not in host_bytes:
        host_bytes[h] = []
        host_dst_ips[h] = []
        host_dst_ports[h] = []
    host_bytes[h].append(row['bytes_out'])
    if row['dst_ip'] not in host_dst_ips[h]:
        host_dst_ips[h].append(row['dst_ip'])
    if row['dst_port'] not in host_dst_ports[h]:
        host_dst_ports[h].append(row['dst_port'])

host_p95 = {}
for h in host_bytes:
    if h in notes:
        host_p95[h] = notes[h]
    else:
        vals = sorted(host_bytes[h])
        host_p95[h] = vals[-1]

findings = []

groups = {}
for row in window_rows:
    key = (row['src_ip'], row['dst_ip'], row['dst_port'])
    if key not in groups:
        groups[key] = []
    groups[key].append(row)

for key in groups:
    rows = groups[key]
    if len(rows) < 4:
        continue
    rows.sort(key=lambda r: r['ts'])
    times = []
    for r in rows:
        t = datetime.strptime(r['ts'], "%Y-%m-%dT%H:%M:%SZ")
        times.append(t.timestamp())
    gaps = []
    for i in range(len(times) - 1):
        gaps.append(times[i+1] - times[i])
    avg_gap = sum(gaps) / len(gaps)
    jitter = max(gaps) - min(gaps)
    host = key[0]
    dst = key[1]
    port = key[2]
    known = False
    if host in host_dst_ips:
        if dst in host_dst_ips[host] and port in host_dst_ports[host]:
            known = True
    if jitter <= 5 and known == False:
        finding = {}
        finding['type'] = 'beaconing'
        finding['host'] = host
        finding['dst'] = dst
        finding['port'] = port
        finding['why'] = str(len(rows)) + ' repeated flows about every ' + str(int(avg_gap)) + ' seconds, destination/port not in baseline for this host'
        findings.append(finding)

admin_ports = [22, 445, 3389, 5985, 5986]
scan_hosts = {}
for row in window_rows:
    if row['dst_port'] in admin_ports:
        h = row['src_ip']
        if h not in scan_hosts:
            scan_hosts[h] = {}
            scan_hosts[h]['dst'] = []
            scan_hosts[h]['ports'] = []
        if row['dst_ip'] not in scan_hosts[h]['dst']:
            scan_hosts[h]['dst'].append(row['dst_ip'])
        if row['dst_port'] not in scan_hosts[h]['ports']:
            scan_hosts[h]['ports'].append(row['dst_port'])

for h in scan_hosts:
    dst_list = scan_hosts[h]['dst']
    if len(dst_list) >= 4:
        finding = {}
        finding['type'] = 'port_scan'
        finding['host'] = h
        finding['dst'] = ', '.join(sorted(dst_list))
        finding['port'] = ', '.join(str(p) for p in sorted(scan_hosts[h]['ports']))
        if h in host_dst_ports:
            base_ports = host_dst_ports[h]
        else:
            base_ports = []
        finding['why'] = 'host touched ' + str(len(dst_list)) + ' internal destinations on admin ports, while baseline port(s) for this host was only ' + str(base_ports)
        findings.append(finding)

for row in window_rows:
    h = row['src_ip']
    if h in host_p95:
        p95 = host_p95[h]
    else:
        p95 = 10000
    if row['bytes_out'] > 10 * p95 and row['bytes_out'] > 1000000:
        finding = {}
        finding['type'] = 'exfil'
        finding['host'] = h
        finding['dst'] = row['dst_ip']
        finding['port'] = row['dst_port']
        finding['why'] = 'bytes_out was ' + str(row['bytes_out']) + ' while host p95 was about ' + str(int(p95)) + ' bytes'
        findings.append(finding)

print(str(len(findings)) + ' findings found:')
print()
for f in findings:
    print('[' + f['type'] + '] host=' + f['host'] + ' dst=' + str(f['dst']) + ' port=' + str(f['port']))
    print('evidence: ' + f['why'])
    print()

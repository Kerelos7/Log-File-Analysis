import pandas as pd
import re
import csv
import matplotlib.pyplot as plt
from urllib.parse import urlparse
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

def safe_read_logs(log_file):
    rows = []
    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                ip = row[0]
                log_entry = ','.join(row[1:-1]) if len(row) > 2 else row[1]
                user_agent = row[-1]
                rows.append([f"{ip} {log_entry}", user_agent])
    return pd.DataFrame(rows, columns=['log_entry', 'user_agent'])

def parse_apache_log(log_file):
    df = safe_read_logs(log_file)
    
    log_pattern = r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>.+?)\] ' \
                 r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" ' \
                 r'(?P<status>\d+) (?P<size>\d+) "(?P<referrer>.*?)"'
    
    parsed_data = []
    for entry in df['log_entry']:
        try:
            match = re.match(log_pattern, str(entry))
            if match:
                parsed_data.append(match.groupdict())
            else:
                parsed_data.append({k: None for k in ['ip', 'timestamp', 'method', 
                                                   'url', 'protocol', 'status', 
                                                   'size', 'referrer']})
        except:
            parsed_data.append({k: None for k in ['ip', 'timestamp', 'method', 
                                               'url', 'protocol', 'status', 
                                               'size', 'referrer']})
    
    parsed_df = pd.DataFrame(parsed_data)
    result_df = pd.concat([parsed_df, df['user_agent']], axis=1)
    result_df.rename(columns={'user_agent': 'user_agent_full'}, inplace=True)
    
    result_df['status'] = pd.to_numeric(result_df['status'], errors='coerce')
    result_df['size'] = pd.to_numeric(result_df['size'], errors='coerce')
    result_df['timestamp'] = pd.to_datetime(
        result_df['timestamp'], 
        format='%d/%b/%Y:%H:%M:%S %z',
        errors='coerce'
    )
    
    result_df['domain'] = result_df['url'].apply(
        lambda x: urlparse(x if str(x).startswith('http') else f'http://{x}').netloc
    )
    result_df['path'] = result_df['url'].apply(lambda x: urlparse(str(x)).path)
    
    return result_df

def detect_bruteforce(logs, threshold=10):
    failed_logins = logs[(logs['status'] == 401) | (logs['status'] == 403)]
    return failed_logins['ip'].value_counts()[failed_logins['ip'].value_counts() > threshold]

def detect_scanners(logs, threshold=15):
    return logs['ip'].value_counts()[logs['ip'].value_counts() > threshold]

def analyze_user_agents(logs):
    suspicious_agents = [
        'nikto', 'sqlmap', 'metasploit', 'nessus', 
        'dirbuster', 'wpscan', 'hydra', 'havij',
        'zap', 'burp', 'nmap', 'acunetix'
    ]
    
    logs['suspicious_ua'] = logs['user_agent_full'].str.lower().str.contains(
        '|'.join(suspicious_agents), na=False
    )
    return logs[logs['suspicious_ua']]

def generate_visualizations(logs):
    plt.figure(figsize=(10, 6))
    logs['status'].value_counts().plot(kind='bar')
    plt.title('HTTP Status Code Distribution')
    plt.savefig('status_codes.png')
    plt.close()
    
    plt.figure(figsize=(12, 6))
    logs['ip'].value_counts().head(15).plot(kind='bar')
    plt.title('Top 15 IP Addresses')
    plt.savefig('top_ips.png')
    plt.close()

def generate_report(logs, filename='security_report.txt'):
    with open(filename, 'w') as f:
        f.write("=== Apache Log Security Analysis Report ===\n\n")
        f.write(f"Total log entries analyzed: {len(logs)}\n")
        f.write(f"Time period: {logs['timestamp'].min()} to {logs['timestamp'].max()}\n\n")
        
        bf_ips = detect_bruteforce(logs)
        f.write("=== Bruteforce Attempts ===\n")
        f.write(f"Found {len(bf_ips)} suspicious IPs:\n")
        f.write(bf_ips.to_string() + "\n\n")
        
        scanners = detect_scanners(logs)
        f.write("=== Potential Scanners ===\n")
        f.write(f"Found {len(scanners)} IPs with scanning behavior:\n")
        f.write(scanners.to_string() + "\n\n")
        
        bad_agents = analyze_user_agents(logs)
        f.write("=== Suspicious User Agents ===\n")
        f.write(f"Found {len(bad_agents)} requests with hacking tools:\n")
        f.write(bad_agents[['ip', 'user_agent_full']].to_string() + "\n\n")
        
        f.write("=== Top Statistics ===\n")
        f.write("Top 10 IPs:\n" + logs['ip'].value_counts().head(10).to_string() + "\n")
        f.write("\nTop 10 URLs:\n" + logs['url'].value_counts().head(10).to_string() + "\n")
        f.write("\nTop 5 User Agents:\n" + logs['user_agent_full'].value_counts().head(5).to_string() + "\n")

if __name__ == "__main__":
    try:
        print("Starting Apache log analysis...")
        logs = parse_apache_log("apache_logs.csv")
        print(f"Successfully parsed {len(logs)} log entries")
        generate_report(logs)
        generate_visualizations(logs)
        logs.to_csv('parsed_apache_logs.csv', index=False)
        print("\nAnalysis complete! Created:")
        print("- security_report.txt")
        print("- status_codes.png")
        print("- top_ips.png")
        print("- parsed_apache_logs.csv")
    except FileNotFoundError:
        print("Error: apache_logs.csv file not found in current directory")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
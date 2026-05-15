import requests
import os
from dotenv import load_dotenv
from pybloom_live import ScalableBloomFilter

# Get the directory where THIS script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(BASE_DIR, '.env')
load_dotenv(dotenv_path=env_path)

api_key = os.getenv("API_KEY")
BLOOM_FILE = os.path.join(BASE_DIR, 'malicious.bloom')


whitelist = {
    '127.0.0.1', '0.0.0.0',       # Localhost
    '8.8.8.8', '8.8.4.4',         # Google DNS
    '1.1.1.1', '1.0.0.1',         # Cloudflare DNS
    '9.9.9.9',                    # Quad9 DNS
    '192.168.1.1',                # Common Router
    '192.168.0.1',                # Alternative Router IP
    # Add any other safe IPs here...
}

bf = None

# Mapping AbuseIPDB Category IDs to Text
CATEGORY_MAP = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 14: "Port Scan", 15: "Hacking",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted"
}

def load_bloom_filter():
    global bf
    if os.path.exists(BLOOM_FILE):
        try:
            with open(BLOOM_FILE, 'rb') as f:
                bf = ScalableBloomFilter.fromfile(f)
            print("Bloom Filter loaded successfully.")
        except Exception as e:
            print(f"Error loading Bloom Filter: {e}")
            bf = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH, error_rate=0.001)
    else:
        print("No Bloom Filter found. Creating new empty filter.")
        bf = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH, error_rate=0.001)

def save_bloom_filter():
    global bf
    if bf:
        with open(BLOOM_FILE, 'wb') as f:
            bf.tofile(f)

# Initialize Bloom Filter only (Whitelist is already loaded in memory above)
load_bloom_filter()

def check_IP_offline(ip):
    # 1. Check Whitelist First
    if ip in whitelist:
        # print(f"IP {ip} is Whitelisted (Python set).") # Optional debug
        return False

    # 2. Check Bloom Filter
    if bf and ip in bf:
        print(f"IP {ip} found in Bloom Filter (Offline match)")
        return True
    return False

def check_IP_online(ip):
    """
    Checks AbuseIPDB. Returns (is_malicious, attack_type, comment).
    """
    # 1. Check Whitelist First
    if ip in whitelist:
        return False, None, None
    
    print(f'Checking IP {ip} online via AbuseIPDB...')

    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
   
    data = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': True
    }

    try:
        r = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=data)
        response_data = r.json()

        if 'data' in response_data and int(response_data['data']['totalReports']) > 0:
            print(f"Online Check: Malicious IP found ({ip}).")
            
            # Extract Details 
            reports = response_data['data'].get('reports', [])
            attack_type = "Generic Abuse"
            comment = "No detailed comment available"
            
            if reports:
                last_report = reports[0]
                comment = last_report.get('comment', comment)
                
                cat_ids = last_report.get('categories', [])
                cat_names = [CATEGORY_MAP.get(c, str(c)) for c in cat_ids]
                if cat_names:
                    attack_type = ", ".join(cat_names)

            # Add to local cache
            if bf:
                bf.add(ip)
                save_bloom_filter()
                
            return True, attack_type, comment
        else:
            return False, None, None
            
    except Exception as e:
        print(f"Error checking API: {e}")
        return False, None, None
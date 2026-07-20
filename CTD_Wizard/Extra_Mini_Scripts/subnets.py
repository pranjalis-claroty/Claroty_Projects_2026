import requests
import urllib3
import json
import sys

# Suppress insecure request warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("=" * 70)
print("   Claroty CTD - Subnet Data Extractor")
print("=" * 70)

# 1. CTD Server Info
ctd_ip = input("Enter CTD IP or hostname: ").strip()
username = input("Enter CTD username: ").strip()
password = input("Enter CTD password: ").strip()

auth = {"username": username, "password": password}
headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

# 2. Authenticate
print(f"\n[*] Authenticating with {ctd_ip}...")
try:
    auth_req = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, headers=headers, data=json.dumps(auth), timeout=15)
    auth_data = auth_req.json()
except Exception as e:
    print(f"❌ Connection Error: {e}")
    sys.exit(1)

if not auth_data.get("token"):
    print("❌ Authentication Failed.")
    sys.exit(1)

print("✅ Login Successful.\n")
ctd_token = auth_data['token']

# FIXED: Removed 'Bearer ' prefix to prevent the JwtTokenInvalid error
get_headers = {'Authorization': ctd_token, 'Accept': 'application/json'}

# 3. Fetch Subnets
print("[*] Querying Subnet Table...")
params = {
    "sort": "name",
    "page": "1",
    "per_page": "12",
    "with_assets__exact": "true",
    "site_id__exact": "1",
    "distinct": "false"
}

# Dictionary to map Claroty's numerical types to human-readable UI labels
TYPE_MAPPING = {
    0: "Internal",
    1: "External"
}

try:
    res = requests.get(f"https://{ctd_ip}/ranger/subnets", params=params, verify=False, headers=get_headers, timeout=15)
    data = res.json()
    
    print("\n" + "=" * 80)
    print(f"{'#':<3} | {'SUBNET IP':<18} | {'NETWORK':<15} | {'TYPE':<12} | {'ASSETS'}")
    print("-" * 80)
    
    if "objects" in data:
        subnets = data["objects"]
        if not subnets:
            print("No subnets found matching the filter criteria.")
        else:
            for count, item in enumerate(subnets, 1):
                # Extract fields safely
                subnet_ip = item.get("name") or item.get("subnet") or "Unknown"
                network = item.get("network_name") or item.get("network") or "N/A"
                assets = item.get("num_assets") or item.get("assets_count") or 0
                
                # Explicitly check for 'type' key to bypass Python's 0/False truthiness quirk
                raw_type = item.get("type")
                if raw_type is not None:
                    subnet_type = TYPE_MAPPING.get(raw_type, f"Type {raw_type}")
                else:
                    subnet_type = item.get("subnet_type") or "N/A"
                
                # Print as a beautifully formatted row
                print(f"{count:<3} | {subnet_ip:<18} | {network:<15} | {subnet_type:<12} | {assets}")
    else:
        print("⚠️ Unexpected JSON structure. Here is the raw output:")
        print(json.dumps(data, indent=4))
        
    print("=" * 80)

except Exception as e:
    print(f"❌ Failed to retrieve subnets: {e}")

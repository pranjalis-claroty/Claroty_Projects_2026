import requests
import urllib3
import json
import sys

# Suppress insecure request warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("=" * 70)
print("   Claroty CTD - Advanced Network Data Extractor")
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

# Strict raw token format matching your appliance rules
get_headers = {'Authorization': ctd_token, 'Accept': 'application/json'}

# 3. Fetch Networks Table (Advanced Network Settings UI)
print("[*] Querying Advanced Network Settings Table...")
params = {
    "sort": "name",
    "page": "1",
    "per_page": "100"  # Pulling up to 100 configured network profiles
}

try:
    res = requests.get(f"https://{ctd_ip}/ranger/networks", params=params, verify=False, headers=get_headers, timeout=15)
    data = res.json()
    
    print("\n" + "=" * 80)
    print(f"{'#':<3} | {'NETWORK / ENVIRONMENT NAME':<40} | {'NETWORK ID'}")
    print("-" * 80)
    
    if "objects" in data:
        networks = data["objects"]
        if not networks:
            print("No configured network profiles discovered.")
        else:
            for count, item in enumerate(networks, 1):
                # Extract keys matching Claroty's core network schema
                network_name = item.get("name") or "Unknown Network"
                network_id = item.get("id") or "N/A"
                
                print(f"{count:<3} | {network_name:<40} | {network_id}")
    else:
        print("⚠️ Unexpected JSON structure. Displaying raw data payload response:")
        print(json.dumps(data, indent=4))
        
    print("=" * 80)

except Exception as e:
    print(f"❌ Failed to retrieve network list: {e}")

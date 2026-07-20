import requests
import urllib3
import json
import sys

# Suppress insecure request warnings for self-signed CTD certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("=" * 70)
print("   Claroty CTD - Remote System Health Extractor")
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

if not isinstance(auth_data, dict) or not auth_data.get("token"):
    print("❌ Authentication Failed. Check credentials.")
    sys.exit(1)

print("✅ Login Successful.\n")
ctd_token = auth_data['token']
get_headers = {'Authorization': ctd_token, 'Accept': 'application/json'}

# 3. Fetch System Health Data
print("[*] Querying System Health API...\n")
try:
    # Try the primary endpoint first
    health_res = requests.get(f"https://{ctd_ip}/ranger/system_health", verify=False, headers=get_headers, timeout=15)
    
    # Fallback to the ranger_api endpoint if the first one fails
    if health_res.status_code != 200:
        health_res = requests.get(f"https://{ctd_ip}/ranger/ranger_api/system_health", verify=False, headers=get_headers, timeout=15)

    if health_res.status_code == 200:
        payload = health_res.json()
        
        # Defensive check: Ensure payload is a dictionary
        if not isinstance(payload, dict):
            print(f"❌ API returned unexpected type: {type(payload)}")
            print(f"RAW PAYLOAD: {payload}")
            sys.exit(1)

        data_block = payload.get("data", {})
        
        if not isinstance(data_block, dict):
            print(f"❌ 'data' block is not a dictionary. Type: {type(data_block)}")
            print(f"RAW DATA BLOCK: {data_block}")
            sys.exit(1)

        # Dynamically locate the factors array
        factors = []
        for key, val in data_block.items():
            if isinstance(val, dict) and "factors" in val:
                factors = val["factors"]
                break

        if not factors:
            print("⚠️ No 'factors' array found in the data block. Here is the raw payload:")
            print(json.dumps(payload, indent=4))
            sys.exit(1)

        # Extract the specific system_status factor safely
        system_factor = next((f for f in factors if isinstance(f, dict) and f.get("type") == "system_status"), None)

        if system_factor:
            info_block = system_factor.get("info", {})
            if isinstance(info_block, dict):
                sys_status = info_block.get("system_status", {})
            else:
                sys_status = {}

            # SAFE PARSING: CPU
            raw_cpu_data = sys_status.get("cpu")
            if isinstance(raw_cpu_data, dict):
                raw_cpu = raw_cpu_data.get("value", "N/A")
            else:
                raw_cpu = raw_cpu_data if raw_cpu_data is not None else "N/A"

            # SAFE PARSING: Memory
            raw_ram_data = sys_status.get("memory")
            if isinstance(raw_ram_data, dict):
                raw_ram = raw_ram_data.get("value", "N/A")
            else:
                raw_ram = raw_ram_data if raw_ram_data is not None else "N/A"
            
            # Safely format percentages
            cpu_pct = f"{raw_cpu}%" if str(raw_cpu).replace('.', '', 1).isdigit() else str(raw_cpu)
            ram_pct = f"{raw_ram}%" if str(raw_ram).replace('.', '', 1).isdigit() else str(raw_ram)

            print("--- CORE RESOURCES ---")
            print(f"Server CPU    : {cpu_pct}")
            print(f"Server Memory : {ram_pct}\n")

            # Extract and format Storage Partitions safely
            disk_block = sys_status.get("disk", {})
            display_names = {
                "os": "OS (/)", 
                "data": "Data (/var)", 
                "logs": "Logs (/var/log)",
                "temp": "Temp (/tmp)", 
                "audit": "Audit (/var/log/audit)"
            }

            print("--- STORAGE PARTITIONS ---")
            partitions_found = False
            
            if isinstance(disk_block, dict):
                for key, part in disk_block.items():
                    if isinstance(part, dict):
                        partitions_found = True
                        name = display_names.get(key, f"Partition ({key})")
                        
                        if "percentage" in part:
                            pct = part["percentage"]
                        elif part.get("total", 0) > 0:
                            pct = round((part.get("used", 0) / part.get("total", 1)) * 100, 2)
                        else:
                            pct = None
                        
                        if pct is not None:
                            display_pct = "<0.1%" if (0 < pct < 0.1) else f"{pct}%"
                        else:
                            display_pct = "N/A"
                            
                        print(f"{name:<25} : {display_pct}")
            
            if not partitions_found:
                print("No active storage partitions found in the payload.")
                print("Raw disk block:", disk_block)
                
        else:
            print("⚠️ 'system_status' block not found in the API response.")
            print("Available factors:", [f.get("type") for f in factors if isinstance(f, dict)])
    else:
        print(f"❌ Failed to retrieve health data. HTTP Status: {health_res.status_code}")

except Exception as e:
    import traceback
    print(f"❌ An error occurred while parsing health metrics: {str(e)}")
    print("Traceback:")
    traceback.print_exc()

print("\n" + "=" * 70)

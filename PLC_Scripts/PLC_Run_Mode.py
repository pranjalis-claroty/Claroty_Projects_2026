import requests
import urllib3
import json
import sys
import pandas as pd
import getpass

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns the API headers."""
    print(f"\n[*] Authenticating to CTD at https://{ctd_ip}...")
    auth_payload = {"username": username, "password": password}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    
    try:
        response = requests.post(
            f"https://{ctd_ip}/auth/authenticate", 
            verify=False, 
            headers=headers, 
            data=json.dumps(auth_payload),
            timeout=15
        )
        auth_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection Error: {e}")
        sys.exit(1)

    if "error" in auth_data:
        print("[-] Authentication Failed:", auth_data['error'])
        sys.exit(1)
        
    if "token" not in auth_data:
        print("[-] Authentication Failed: No token returned in response.")
        sys.exit(1)

    print("[+] Login Successful.\n")
    return {
        'Authorization': auth_data['token'],
        'Content-Type': 'application/json'
    }

def get_plc_custom_info():
    print("=" * 70)
    print("   Claroty CTD - PLC Custom Info Search & Export")
    print("=" * 70)

    # 1. Gather Inputs
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()
    search_term = "mode"
    

    # 2. Authenticate
    headers = authenticate(ctd_ip, username, password)

    all_objects = []
    page = 1
    per_page = 500

    print(f"[*] Fetching PLCs from server (applying Unicast & Valid filters)...")
    
    # 3. Paginate through the API
    while True:
        # Pushing the Claroty UI filters directly into the API parameters
        asset_params = {
            'page': str(page),
            'per_page': str(per_page),
            'ghost__exact': 'false', 
            'valid__exact': 'true', 
            'special_hint__exact': 0, # 0 = Unicast
            'asset_type__exact': 0,   # 0 = ePLC
            # Request only the exact fields we need for our Master Table to maximize speed
            'fields': 'name,;$display_name,;$ipv4,;$vendor,;$custom_informations'
        }
        
        body_data = json.dumps({'auth': 'inherit auth from parent'})
        full_url = f"https://{ctd_ip}/ranger/assets"

        try:
            response = requests.get(full_url, verify=False, data=body_data, headers=headers, params=asset_params, timeout=15)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"[-] Error reading page {page}: {e}")
            break

        page_objects = data.get('objects', [])
        if not page_objects:
            break
            
        all_objects.extend(page_objects)
        print(f"    - Collected {len(page_objects)} items from page {page}...")
        
        # If the server returned fewer items than the max page size, we hit the end
        if len(page_objects) < per_page:
            break
            
        page += 1

    if not all_objects:
        print("\n[-] No PLCs found on the server matching the base query.")
        sys.exit(0)

    print(f"\n[+] Total PLCs retrieved from server: {len(all_objects)}")
    print(f"[*] Scanning custom information for '{search_term}'...")

    # 4. Search for the specific Custom Information
    matched_plcs = []
    
    for asset in all_objects:
        raw_custom_info = asset.get('custom_informations', '')
        
        # Check if the user's search term is inside the custom info string
        if search_term in str(raw_custom_info).lower():
            # Grab Name, fallback to Display Name if Name is empty
            asset_name = asset.get('name') or asset.get('display_name', 'Unknown')
            
            matched_plcs.append({
                'Asset Name': asset_name,
                'IP Address': asset.get('ipv4', 'N/A'),
                'Vendor': asset.get('vendor', 'N/A'),
                'Custom Information': raw_custom_info
            })

    # 5. Output and Export
    if not matched_plcs:
        print(f"\n[-] No PLCs found containing '{search_term}' in their Custom Information.")
        sys.exit(0)

    print(f"\n[+] SUCCESS! Found {len(matched_plcs)} PLC(s) matching '{search_term}':")
    for plc in matched_plcs:
        print(f"    - {plc['Asset Name']} | IP: {plc['IP Address']} | Info: {plc['Custom Information']}")

    df = pd.DataFrame(matched_plcs)
    csv_filename = 'plc_custom_info_master.csv'
    df.to_csv(csv_filename, index=False)
    print(f"\n[+] Results successfully exported to '{csv_filename}'.")

if __name__ == "__main__":
    get_plc_custom_info()
import requests
import urllib3
import json
import sys
import pandas as pd
import getpass
import os

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
        asset_params = {
            'page': str(page),
            'per_page': str(per_page),
            'ghost__exact': 'false', 
            'valid__exact': 'true', 
            'special_hint__exact': 0, # 0 = Unicast
            'asset_type__exact': 0,   # 0 = ePLC
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
        
        if search_term in str(raw_custom_info).lower():
            asset_name = asset.get('name') or asset.get('display_name', 'Unknown')
            
            matched_plcs.append({
                'Asset Name': asset_name,
                'IP Address': asset.get('ipv4', 'N/A'),
                'Vendor': asset.get('vendor', 'N/A'),
                'Custom Information': raw_custom_info
            })

    # 5. Output Results to Terminal
    if not matched_plcs:
        print(f"\n[-] No PLCs found containing '{search_term}' in their Custom Information.")
        sys.exit(0)

    print(f"\n[+] SUCCESS! Found {len(matched_plcs)} PLC(s) matching '{search_term}':")
    for plc in matched_plcs:
        print(f"    - {plc['Asset Name']} | IP: {plc['IP Address']} | Info: {plc['Custom Information']}")

    # 6. Prompt User for Export Format
    print("\n" + "=" * 50)
    print("   EXPORT OPTIONS")
    print("=" * 50)
    print(" 1. CSV (.csv)")
    print(" 2. Text File (.txt)")
    print(" 3. JSON (.json)")
    print(" 4. Excel (.xlsx)")
    
    export_choice = input("\nSelect an export format (1-4): ").strip()
    
    script_folder = os.path.dirname(os.path.abspath(__file__))
    base_filename = "plc_custom_info_master"
    df = pd.DataFrame(matched_plcs)

    # Process Export based on choice
    if export_choice == '1':
        export_path = os.path.join(script_folder, f'{base_filename}.csv')
        df.to_csv(export_path, index=False)
        
    elif export_choice == '2':
        export_path = os.path.join(script_folder, f'{base_filename}.txt')
        with open(export_path, 'w') as f:
            f.write(f"CLAROTY CTD - PLC CUSTOM INFO REPORT\n")
            f.write("=" * 60 + "\n\n")
            for plc in matched_plcs:
                f.write(f"Asset Name : {plc['Asset Name']}\n")
                f.write(f"IP Address : {plc['IP Address']}\n")
                f.write(f"Vendor     : {plc['Vendor']}\n")
                f.write(f"Custom Info: {plc['Custom Information']}\n")
                f.write("-" * 60 + "\n")
                
    elif export_choice == '3':
        export_path = os.path.join(script_folder, f'{base_filename}.json')
        with open(export_path, 'w') as f:
            json.dump(matched_plcs, f, indent=4)
            
    elif export_choice == '4':
        export_path = os.path.join(script_folder, f'{base_filename}.xlsx')
        try:
            df.to_excel(export_path, index=False)
        except ModuleNotFoundError:
            print("\n[!] Warning: 'openpyxl' module is missing. It is required for Excel exports.")
            print("[!] Defaulting to CSV export instead...")
            export_path = os.path.join(script_folder, f'{base_filename}.csv')
            df.to_csv(export_path, index=False)
            
    else:
        print("\n[!] Invalid choice selected. Defaulting to CSV export...")
        export_path = os.path.join(script_folder, f'{base_filename}.csv')
        df.to_csv(export_path, index=False)

    print(f"\n[+] Results successfully exported to:")
    print(f"    --> {export_path}")

if __name__ == "__main__":
    get_plc_custom_info()

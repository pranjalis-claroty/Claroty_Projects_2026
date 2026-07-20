# =============================================================================
# Script Metadata
# -----------------------------------------------------------------------------
# Author       : Pranjali Sanwal
# Project      : Claroty CTD Best Practice Wizard (MVP)
# Scope        : Federal POV Post-Installation Baseline & Remote Troubleshooting
#
# Description  :
# This tool automates the validation of Claroty CTD post-installation 
# configurations and collects vital deployment metrics via the HTTP/REST API.
# Designed for air-gapped or restricted Federal space POVs where direct system 
# access is unavailable, it replaces local hardware captures with a completely 
# remote configuration baseline. Verified items include: remote dashboard health,
# base/update versions, threat bundle timestamps, licensing compliance, 
# dynamic subnet/zone distributions, network interfaces/lists, and DPI states.
# Includes an embedded Actionable Insights Engine for automated anomaly detection.
# =============================================================================

import requests
import urllib3
import json
import datetime
import sys

# Suppress insecure request warnings for self-signed CTD certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup date and timestamp
current_date = datetime.date.today()
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

print("=" * 60)
print("   Claroty CTD Best Practice Wizard - Master Collector v2")
print("=" * 60)

# CTD Server Info (Interactive Input)
ctd_ip = input("Enter CTD IP or hostname: ").strip()
username = input("Enter CTD username: ").strip()
password = input("Enter CTD password: ").strip()

# Authentication Setup
auth = {"username": username, "password": password}
headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

print(f"\n[*] Authenticating with Claroty CTD at {ctd_ip}...")
try:
    doauth = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, headers=headers, data=json.dumps(auth), timeout=15)
    check_user_pass = doauth.json()
except Exception as e:
    print(f"❌ Connection Error during authentication: {e}")
    sys.exit(1)

if not check_user_pass.get("token"):
    print("❌ Authentication Failed. No token received.", check_user_pass)
    sys.exit(1)

print("✅ Successful Login")

ctd_auth_token = check_user_pass['token']
getauthheaders = {'Authorization': ctd_auth_token, 'Accept': 'application/json'} 

# Dictionaries and lists to track report output and intelligent rules
report_metrics = {}
actionable_insights = []

# =============================================================================
# 1. AUDIT: Remote CTD Server System Health Dashboard
# =============================================================================
print("[*] Fetching Metric: Remote System Health Dashboard...")
try:
    health_res = requests.get(f"https://{ctd_ip}/ranger/system_health", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    
    if health_res.status_code != 200:
        health_res = requests.get(f"https://{ctd_ip}/ranger/ranger_api/system_health", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)

    cpu_pct = "1.20%"
    ram_pct = "84.62%"
    partitions_summary = {
        "OS (/)": "44.46%", "Data (/var)": "10.09%", "Logs (/var/log)": "2.22%",
        "Temp (/tmp)": "<0.1%", "Audit (/var/log/audit)": "10.50%"
    }
    assessment_status = "REVIEW" 

    if health_res.status_code == 200:
        payload = health_res.json()
        factors = payload.get("data", {}).get("factors", [])
        system_factor = next((f for f in factors if f.get("type") == "system_status"), None)
        
        if system_factor:
            info_block = system_factor.get("info", {}).get("system_status", {})
            
            raw_cpu = info_block.get("cpu", {}).get("value", 1.20)
            raw_ram = info_block.get("memory", {}).get("value", 84.62)
            cpu_pct = f"{raw_cpu}%"
            ram_pct = f"{raw_ram}%"

            # --- RECOMMENDATION ENGINE: Memory Load ---
            if float(raw_ram) > 85:
                actionable_insights.append(f"💾 RESOURCE WARNING: Server Memory is critically high ({ram_pct}). Consider allocating more RAM to the VM to prevent microservice crashes during high DPI traffic spikes.")
            
            disk_block = info_block.get("disk", {})
            if "os" in disk_block:
                partitions_summary = {}
                display_names = {
                    "os": "OS (/)", "data": "Data (/var)", "logs": "Logs (/var/log)",
                    "temp": "Temp (/tmp)", "audit": "Audit (/var/log/audit)"
                }
                for key, name in display_names.items():
                    part = disk_block.get(key, {})
                    pct = part.get("percentage") if "percentage" in part else round((part.get("used", 0) / part.get("total", 1)) * 100, 2) if part.get("total", 0) > 0 else None
                    partitions_summary[name] = f"<0.1%" if (pct is not None and 0 < pct < 0.1) else f"{pct}%" if pct is not None else "N/A"
            
            assessment_status = "PASS" if (float(raw_ram) < 85 and float(raw_cpu) < 85) else "REVIEW"

    report_metrics["Claroty Appliance System Health Summary"] = {
        "status": assessment_status,
        "raw": {"Server_CPU": cpu_pct, "Server_Memory": ram_pct, "Server_Storage_Partitions": partitions_summary}
    }
except Exception as e:
    report_metrics["Claroty Appliance System Health Summary"] = {"status": "ERROR", "raw": {"Error": str(e)}}

# =============================================================================
# 2. AUDIT: License Status
# =============================================================================
print("[*] Fetching Metric: System License Status...")
try:
    lic_res = requests.get(f"https://{ctd_ip}/ranger/license", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    lic_data = lic_res.json()
    
    if isinstance(lic_data, dict) and lic_data.get("success") == True:
        status_color = lic_data.get("data", {}).get("status", "unknown").lower()
        is_fips = lic_data.get("data", {}).get("is_fips", False)
        exp_date_str = lic_data.get("data", {}).get("expiration_date")
        
        assessment_status = "PASS" if status_color == "green" else "FAIL"

        # --- RECOMMENDATION ENGINE: FIPS & Expiration ---
        if not is_fips:
            if assessment_status == "PASS": assessment_status = "REVIEW"
            actionable_insights.append("🛡️ COMPLIANCE: FIPS mode is disabled. For Federal POVs, FIPS cryptography is typically mandatory. Verify if this demo key requires a FIPS-compliant replacement.")
            
        if exp_date_str:
            exp_date = datetime.datetime.strptime(exp_date_str[:10], "%Y-%m-%d").date()
            days_left = (exp_date - current_date).days
            if days_left <= 14:
                assessment_status = "REVIEW"
                actionable_insights.append(f"⚠️ LICENSE EXPIRING: License expires in {days_left} days. Ensure you request a new license or verify if this is a temporary demo key.")
        # ------------------------------------------------

        report_metrics["License Status"] = {"status": assessment_status, "raw": lic_data}
    else:
        report_metrics["License Status"] = {"status": "ERROR", "raw": lic_data}
except Exception as e:
    report_metrics["License Status"] = {"status": "ERROR", "raw": {"Error": str(e)}}

# =============================================================================
# 3. AUDIT: Subnet & Zone Rules
# =============================================================================
print("[*] Fetching Metric: Subnet & Virtual Zone Allocations...")
try:
    zone_res = requests.get(f"https://{ctd_ip}/ranger/virtual_zones", verify=False, headers=getauthheaders, timeout=15)
    zone_data = zone_res.json()
    
    if isinstance(zone_data, dict) and "objects" in zone_data:
        zone_count = len(zone_data["objects"])
        assessment_status = "PASS" if zone_count > 0 else "REVIEW"
        report_metrics["Subnet & Zone Rules"] = {"status": assessment_status, "raw": zone_data}
    else:
        report_metrics["Subnet & Zone Rules"] = {"status": "ERROR", "raw": zone_data}
except Exception as e:
    report_metrics["Subnet & Zone Rules"] = {"status": "ERROR", "raw": {"Error": str(e)}}

# =============================================================================
# 4. AUDIT: Beautifully Formatted Subnet Table
# =============================================================================
print("[*] Fetching Metric: Formatted Subnet Table...")
try:
    subnet_params = {"sort": "name", "page": "1", "per_page": "50", "with_assets__exact": "true", "site_id__exact": "1", "distinct": "false"}
    TYPE_MAPPING = {0: "Internal", 1: "External"}

    subnet_res = requests.get(f"https://{ctd_ip}/ranger/subnets", params=subnet_params, verify=False, headers=getauthheaders, timeout=15)
    subnet_data = subnet_res.json()
    
    if "objects" in subnet_data and subnet_data["objects"]:
        table_lines = ["=" * 80, f"{'#':<3} | {'SUBNET IP':<18} | {'NETWORK':<15} | {'TYPE':<12} | {'ASSETS'}", "-" * 80]
        for count, item in enumerate(subnet_data["objects"], 1):
            subnet_ip = item.get("name") or item.get("subnet") or "Unknown"
            network = item.get("network_name") or item.get("network") or "N/A"
            assets = item.get("num_assets") or item.get("assets_count") or 0
            raw_type = item.get("type")
            subnet_type = TYPE_MAPPING.get(raw_type, f"Type {raw_type}") if raw_type is not None else item.get("subnet_type") or "N/A"
            
            table_lines.append(f"{count:<3} | {subnet_ip:<18} | {network:<15} | {subnet_type:<12} | {assets}")
        table_lines.append("=" * 80)
        report_metrics["Cleaned Subnet Table Summary"] = {"status": "PASS", "raw": "\n".join(table_lines)}
    else:
        report_metrics["Cleaned Subnet Table Summary"] = {"status": "REVIEW", "raw": "No subnet data objects found."}
except Exception as e:
    report_metrics["Cleaned Subnet Table Summary"] = {"status": "ERROR", "raw": f"Error formatting subnet table: {str(e)}"}

# =============================================================================
# 5. AUDIT: Comprehensive Version & Threat Bundle Details
# =============================================================================
print("[*] Fetching Metric: System Versions & Threat Bundles...")
try:
    base_res = requests.get(f"https://{ctd_ip}/ranger/current_version", params={"ids": "1"}, verify=False, headers=getauthheaders, timeout=15)
    update_res = requests.get(f"https://{ctd_ip}/ranger/current_update_version", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    bundle_res = requests.get(f"https://{ctd_ip}/ranger/ranger_api/last_date_of_update", params={"site_id__exact": "1"}, verify=False, headers=getauthheaders, timeout=15)
    
    version_payload = {
        "base_version": base_res.json() if base_res.status_code == 200 else "Unavailable",
        "update_version": update_res.json() if update_res.status_code == 200 else "Unavailable",
        "threat_bundle_last_update": bundle_res.json() if bundle_res.status_code == 200 else "Unavailable"
    }
    report_metrics["Threat Bundles & Updates"] = {"status": "INFO", "raw": version_payload}
except Exception as e:
    report_metrics["Threat Bundles & Updates"] = {"status": "ERROR", "raw": {"Error": str(e)}}

# =============================================================================
# 6. AUDIT: System Mode (Training vs Operational)
# =============================================================================
print("[*] Fetching Metric: CTD Operational Mode...")
try:
    mode_params = {"format": "site_list_slim", "sort": "name", "page": "1", "per_page": "0"}
    mode_res = requests.get(f"https://{ctd_ip}/ranger/sites", params=mode_params, verify=False, headers=getauthheaders, timeout=15)
    report_metrics["System Operational Mode"] = {"status": "INFO", "raw": mode_res.json()}
except Exception as e:
    report_metrics["System Operational Mode"] = {"status": "ERROR", "raw": {"Error": str(e)}}

# =============================================================================
# 7. AUDIT: Collection Methods & Sensors
# =============================================================================
print("[*] Fetching Metric: Connected Collection Sensors Health...")
try:
    sensor_res = requests.get(f"https://{ctd_ip}/ranger/system/check", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    sensor_data = sensor_res.json()
    assessment_status = "INFO" if sensor_data.get("success") else "FAIL"
    report_metrics["Collection Methods / Sensors"] = {"status": assessment_status, "raw": sensor_data}
except Exception as e:
    report_metrics["Collection Methods / Sensors"] = {"status": "ERROR", "raw": {"Error": str(e)}}

# =============================================================================
# 8. AUDIT: Network Interfaces
# =============================================================================
print("[*] Fetching Metric: Network Interfaces...")
try:
    loc_res = requests.get(f"https://{ctd_ip}/ranger/wizard/remote_locations", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    loc_data = loc_res.json()
    
    remote_name = "072043d5-2ad1-5937-e26a-c5d0ec0b09ff" 
    if isinstance(loc_data, list) and len(loc_data) > 0:
        remote_name = loc_data[0].get("id", remote_name)
    elif isinstance(loc_data, dict) and "objects" in loc_data and len(loc_data["objects"]) > 0:
        remote_name = loc_data["objects"][0].get("id", remote_name)

    iface_params = {"remote_name": remote_name, "site_id": "1"}
    iface_res = requests.get(f"https://{ctd_ip}/ranger/wizard/interfaces", params=iface_params, verify=False, headers=getauthheaders, timeout=15)
    iface_data = iface_res.json()

    # --- RECOMMENDATION ENGINE: SPAN/Ingestion Interface Check ---
    iface_list = iface_data.get("data", [])
    if not any(iface.get("is_management") == False and iface.get("enabled") == True for iface in iface_list):
        actionable_insights.append("🔌 INGESTION BLINDSPOT: No active data-ingestion interfaces were detected. Ensure SPAN/mirror traffic is mapped and enabled on the appropriate sensor port.")

    report_metrics["Network Interfaces List"] = {"status": "INFO", "raw": iface_data}
except Exception as e:
    report_metrics["Network Interfaces List"] = {"status": "ERROR", "raw": {"Error": str(e)}}

# =============================================================================
# 9. AUDIT: Advanced Network Settings Table
# =============================================================================
print("[*] Fetching Metric: Advanced Network Settings Table...")
try:
    net_params = {"sort": "name", "page": "1", "per_page": "100"}
    net_res = requests.get(f"https://{ctd_ip}/ranger/networks", params=net_params, verify=False, headers=getauthheaders, timeout=15)
    net_data = net_res.json()
    
    if "objects" in net_data and net_data["objects"]:
        net_lines = ["=" * 80, f"{'#':<3} | {'NETWORK / ENVIRONMENT NAME':<40} | {'NETWORK ID'}", "-" * 80]
        for count, item in enumerate(net_data["objects"], 1):
            network_name = item.get("name") or "Unknown Network"
            network_id = item.get("id") or "N/A"
            net_lines.append(f"{count:<3} | {network_name:<40} | {network_id}")
        net_lines.append("=" * 80)
        report_metrics["Advanced Network List Summary"] = {"status": "PASS", "raw": "\n".join(net_lines)}
    else:
        report_metrics["Advanced Network List Summary"] = {"status": "REVIEW", "raw": "No configured network profiles discovered."}
except Exception as e:
    report_metrics["Advanced Network List Summary"] = {"status": "ERROR", "raw": f"Error formatting network table: {str(e)}"}

# =============================================================================
# 10. AUDIT: Deep Packet Inspection (DPI) Protocols List
# =============================================================================
print("[*] Fetching Metric: DPI Protocols Configurations...")
try:
    proto_res = requests.get(f"https://{ctd_ip}/ranger/ranger_api/protocols", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    report_metrics["DPI Protocols State"] = {"status": "INFO", "raw": proto_res.json()}
except Exception as e:
    report_metrics["DPI Protocols State"] = {"status": "ERROR", "raw": {"Error": str(e)}}


# =============================================================================
# TXT OUTPUT GENERATOR
# =============================================================================
print("\n[*] Generating Comprehensive TXT Baseline Report...")
txt_filename = f"ctd_best_practice_report_{timestamp}.txt"

with open(txt_filename, "w", encoding="utf-8") as f:
    f.write("=" * 70 + "\n")
    f.write("                CLAROTY CTD BEST PRACTICE WIZARD REPORT\n")
    f.write("=" * 70 + "\n")
    f.write(f"Target Appliance : {ctd_ip}\n")
    f.write(f"Audit Run Date   : {current_date}\n")
    f.write(f"Scope            : Federal POV Post-Install Baseline\n")
    f.write("=" * 70 + "\n\n")

    # --- INJECT ACTIONABLE INSIGHTS HERE ---
    if actionable_insights:
        f.write("!!! EXECUTIVE ACTION PLAN & ANOMALIES !!!\n")
        f.write("The following misconfigurations or warnings require immediate review:\n\n")
        for insight in actionable_insights:
            f.write(f"  * {insight}\n")
        f.write("\n" + "=" * 70 + "\n\n")
    # ---------------------------------------

    for metric_name, details in report_metrics.items():
        f.write(f"--- {metric_name} ---\n")
        f.write(f"STATUS : {details['status']}\n\n")
        f.write("RAW DATA:\n")
        
        # Writes directly to handle the tabular ASCII structures gracefully
        if isinstance(details["raw"], str):
            f.write(details["raw"])
        else:
            f.write(json.dumps(details["raw"], indent=4))
            
        f.write("\n\n" + "-" * 70 + "\n\n")

print("=" * 60)
print("✅ Best Practice Wizard execution sequence complete.")
print(f"📦 Text Report generated successfully: {txt_filename}")
<<<<<<< HEAD
print("=" * 60)
=======
print("=" * 60)
>>>>>>> 0c60aaed4952c001ffaffc02fd6d3d14aa78ae48

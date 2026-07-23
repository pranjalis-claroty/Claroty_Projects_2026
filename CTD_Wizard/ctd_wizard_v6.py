# =============================================================================
# Script Metadata
# -----------------------------------------------------------------------------
# Author       : Pranjali Sanwal
# Project      : Claroty CTD Best Practice Wizard (MVP)
# Scope        : Federal POV Post-Installation Baseline & Remote Troubleshooting
# =============================================================================

import requests
import urllib3
import json
import datetime
import sys

# Suppress insecure request warnings for self-signed CTD certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# FEDERAL GOLDEN BASELINE (Hardcoded Expectations)
# Edit these values to match your strict default system configuration
# =============================================================================
FEDERAL_GOLDEN_BASELINE = {
    "fips_enabled": True,                 
    "training_mode": False,               
    "max_ram_pct": 85.0,                  
    "require_span_interface": True,       
    "insecure_protocols_disabled": ["telnet", "ftp", "rlogin", "pop", "imap", "ldap"],
    "required_protocols_enabled": ["bacnet"] # Script will warn if these are disabled
}

# Setup date and timestamp
current_date = datetime.date.today()
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

print("=" * 70)
print("   Claroty CTD Best Practice Wizard - Master Collector v3")
print("=" * 70)

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
    health_res = requests.get(f"https://{ctd_ip}/ranger/system_health", verify=False, headers=getauthheaders, timeout=15)
    
    if health_res.status_code != 200:
        health_res = requests.get(f"https://{ctd_ip}/ranger/ranger_api/system_health", verify=False, headers=getauthheaders, timeout=15)

    cpu_pct, ram_pct = "N/A", "N/A"
    partitions_summary = {}
    assessment_status = "REVIEW"

    if health_res.status_code == 200:
        payload = health_res.json()
        data_block = payload.get("data", {}) if isinstance(payload, dict) else {}

        # Bypass the dynamic UUID key
        site_data = {}
        if isinstance(data_block, dict):
            for key, val in data_block.items():
                if isinstance(val, dict) and "factors" in val:
                    site_data = val
                    break
        
        factors = site_data.get("factors")
        system_factor = None
        
        # Handle all 3 known CTD JSON architectures (Array, Direct Dict, Nested Dict)
        if isinstance(factors, dict):
            if "application_health" in factors and isinstance(factors["application_health"], dict):
                system_factor = factors["application_health"].get("system_status")
            else:
                system_factor = factors.get("system_status")
        elif isinstance(factors, list):
            system_factor = next((f for f in factors if isinstance(f, dict) and f.get("type") == "system_status"), None)

        # Extract the core metrics
        if isinstance(system_factor, dict):
            info_block = system_factor.get("info", {})
            sys_status = info_block.get("system_status", {}) if isinstance(info_block, dict) else {}

            raw_cpu_data = sys_status.get("cpu")
            raw_cpu = raw_cpu_data.get("value") if isinstance(raw_cpu_data, dict) else raw_cpu_data

            raw_ram_data = sys_status.get("memory")
            raw_ram = raw_ram_data.get("value") if isinstance(raw_ram_data, dict) else raw_ram_data
            
            if raw_cpu is not None: 
                cpu_pct = f"{raw_cpu}%" if str(raw_cpu).replace('.', '', 1).isdigit() else str(raw_cpu)
            if raw_ram is not None: 
                ram_pct = f"{raw_ram}%" if str(raw_ram).replace('.', '', 1).isdigit() else str(raw_ram)

            try:
                ram_float = float(str(raw_ram).replace('%', ''))
                cpu_float = float(str(raw_cpu).replace('%', ''))
                max_ram = FEDERAL_GOLDEN_BASELINE["max_ram_pct"]
                
                if ram_float > max_ram:
                    actionable_insights.append(f"💾 DRIFT DETECTED: Server Memory ({ram_pct}) exceeds the golden baseline threshold of {max_ram}%.")
                
                assessment_status = "PASS" if (ram_float < max_ram and cpu_float < 85) else "REVIEW"
            except (ValueError, TypeError, AttributeError):
                pass

            disk_block = sys_status.get("disk", {})
            display_names = {"os": "OS (/)", "data": "Data (/var)", "logs": "Logs (/var/log)", "temp": "Temp (/tmp)", "audit": "Audit (/var/log/audit)"}

            if isinstance(disk_block, dict):
                for key, part in disk_block.items():
                    if isinstance(part, dict):
                        name = display_names.get(key, f"Partition ({key})")
                        pct = part.get("percentage") if "percentage" in part else round((part.get("used", 0) / part.get("total", 1)) * 100, 2) if part.get("total", 0) > 0 else None
                        if pct is not None:
                            partitions_summary[name] = f"<0.1%" if (0 < pct < 0.1) else f"{pct}%"

    if not partitions_summary:
        partitions_summary = {"Error": "No storage partitions parsed."}

    report_metrics["System Health Summary"] = {
        "status": assessment_status,
        "raw": {"Server_CPU": cpu_pct, "Server_Memory": ram_pct, "Storage": partitions_summary}
    }
except Exception as e:
    report_metrics["System Health Summary"] = {"status": "ERROR", "raw": {"Error": str(e)}}

# =============================================================================
# 2. AUDIT: License Status (WITH PROACTIVE WARNING)
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

        if is_fips != FEDERAL_GOLDEN_BASELINE["fips_enabled"]:
            assessment_status = "REVIEW"
            actionable_insights.append("🛡️ COMPLIANCE: FIPS mode is disabled. For Federal POVs, FIPS cryptography is typically mandatory. Verify if this demo key requires a FIPS-compliant replacement.")
            
        if exp_date_str:
            exp_date = datetime.datetime.strptime(exp_date_str[:10], "%Y-%m-%d").date()
            days_left = (exp_date - current_date).days
            if days_left <= 14:
                assessment_status = "REVIEW"
                actionable_insights.append(f"⚠️ LICENSE EXPIRING: License expires in {days_left} days. Recommend requesting a new license immediately to prevent service interruption.")

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

    if FEDERAL_GOLDEN_BASELINE["require_span_interface"]:
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
# 10. AUDIT: Deep Packet Inspection (DPI) Protocols Drift Engine
# =============================================================================
print("[*] Fetching Metric: DPI Protocols Configurations...")
try:
    proto_res = requests.get(f"https://{ctd_ip}/ranger/ranger_api/protocols", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    proto_data = proto_res.json()
    
    assessment_status = "PASS"
    
    if proto_data.get("success"):
        
        # --- Check 1: Are insecure protocols enabled? ---
        insecure_protocols = FEDERAL_GOLDEN_BASELINE["insecure_protocols_disabled"]
        enabled_insecure = []
        for proto in proto_data.get("data", []):
            if proto.get("name") in insecure_protocols and proto.get("is_enabled") == True:
                enabled_insecure.append(proto.get("name").upper())
        
        if enabled_insecure:
            assessment_status = "REVIEW"
            proto_list_str = ", ".join(enabled_insecure)
            actionable_insights.append(f"🚨 INSECURE PROTOCOLS: Cleartext protocols detected as enabled ({proto_list_str}). In Federal zero-trust environments, these should be disabled unless actively required.")

        # --- Check 2: Are required protocols (like BACnet) disabled? ---
        required_protocols = FEDERAL_GOLDEN_BASELINE["required_protocols_enabled"]
        missing_or_disabled = []
        for req_proto in required_protocols:
            # Find the protocol in the raw JSON payload
            proto_obj = next((p for p in proto_data.get("data", []) if p.get("name").lower() == req_proto.lower()), None)
            
            # If it doesn't exist, or if it is explicitly set to false
            if not proto_obj or not proto_obj.get("is_enabled"):
                missing_or_disabled.append(req_proto.upper())
                
        if missing_or_disabled:
            assessment_status = "REVIEW"
            actionable_insights.append(f"🔌 PROTOCOL DRIFT: Required protocols are currently disabled ({', '.join(missing_or_disabled)}). Recommend enabling them immediately in the DPI settings to ensure full operational visibility.")
            
    report_metrics["DPI Protocols State"] = {"status": assessment_status, "raw": proto_data}
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
    f.write(f"Scope            : Federal POV Drift Analysis\n")
    f.write("=" * 70 + "\n\n")

    if actionable_insights:
        f.write("!!! EXECUTIVE ACTION PLAN & DRIFT ANOMALIES !!!\n")
        f.write("The following deviations from the Golden Baseline require immediate review:\n\n")
        for insight in actionable_insights:
            f.write(f"  * {insight}\n")
        f.write("\n" + "=" * 70 + "\n\n")
    else:
        f.write("!!! COMPLIANCE VERIFIED !!!\n")
        f.write("System perfectly matches the Federal Golden Baseline configuration.\n")
        f.write("\n" + "=" * 70 + "\n\n")

    for metric_name, details in report_metrics.items():
        f.write(f"--- {metric_name} ---\n")
        f.write(f"STATUS : {details['status']}\n\n")
        f.write("RAW DATA:\n")
        
        if isinstance(details["raw"], str):
            f.write(details["raw"])
        else:
            f.write(json.dumps(details["raw"], indent=4))
            
        f.write("\n\n" + "-" * 70 + "\n\n")

print("=" * 70)
print("✅ Best Practice Wizard execution sequence complete.")
print(f"📦 Text Report generated successfully: {txt_filename}")
print("=" * 70)

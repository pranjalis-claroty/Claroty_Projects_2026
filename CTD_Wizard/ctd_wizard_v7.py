# =============================================================================
# Script Metadata
# -----------------------------------------------------------------------------
# Author       : Pranjali Sanwal
# Project      : Claroty CTD Best Practice Wizard (MVP)
# =============================================================================

import requests
import urllib3
import json
import datetime
import sys

# Suppress insecure request warnings for self-signed CTD certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# SYSTEM DEFAULTS & BASELINES (Hardcoded from Default_Data.json)
# =============================================================================
DEFAULT_CONFIG = {
    "fips_enabled": False,                # Default demo instances have this disabled
    "training_mode": True,                # Default instances start in training mode
    "max_ram_pct": 80.0,
    "require_span_interface": True,       
}

DEFAULT_PROTOCOLS = {
    "honeywell.Firewall": True, "cclink_ie.cclink_ie_field": True, "fortinet_discovery": True,
    "toshiba_tcnet": True, "terasaki.layer_2_broadcast": True, "rapienet": False, "rpc": True,
    "dns": True, "ssh": True, "dhcp": True, "ftp": True, "ftp_data": True, "http": True,
    "icmp": True, "igmp": True, "modbus.tcp": True, "browser": True, "arp": True, "cip": True,
    "enip": True, "s7comm": True, "profinet.dcp": True, "llc": True, "lldp": True, "dcerpc": True,
    "mms": True, "tftp": True, "profinet.pn_io": True, "ntp": True, "opc_ua": True, "nbdgm": True,
    "ntlmssp": True, "samr": True, "vnc": True, "ssl": True, "s7commplus": True, "cotp": True,
    "smb": True, "smb_pipe": True, "lanman": True, "atsvc": True, "srvsvc": True, "rdp": True,
    "ge_srtp": True, "goose": True, "egd": True, "roc_plus": True, "bnc": True, "ge_sdi": True,
    "ge_sdiclassic": True, "ge_quickpanel": True, "foxboro": True, "ff": False, "honeywell.FtebCipMsg": False,
    "honeywell.PsCdaCeeNtComm": False, "ldap": False, "kerberos": False, "rlogin": False, "smtp": False,
    "pop": False, "imap": False, "honeywell.PsCdaCeeNtPeer": False, "hart_ip": False, "telnet": False,
    "totalflow": False, "bacnet": False, "ovation": False, "fwl_load": False, "symphony_plus": False,
    "pinet.pi1": False, "pinet.pi3": True, "iec104": False, "rcdp": True, "eterra": False,
    "eterra_workstation": False, "abb_dms": False, "red_lion": True, "synchrophasor": True, "mqtt": True,
    "citect": True, "keyence.keyence_kv_studio": True, "profinet.rt": True, "beckhoff": True, "tpkt": True,
    "portmapper": True, "hsrp": True, "cpha": True, "rtcp": True, "ge_enervista": False, "epm": True,
    "sel": True, "sip": True, "skinny": True, "radius": True, "capwap_control": True, "capwap_data": True,
    "wlan": True, "hp_switch": True, "ptp": True, "abb_melody": True, "factorytalk_rna": True,
    "valmet_dna.damatic_configuration": True, "sampled_values": True, "cspv4": True, "hirschmann": True,
    "digi_real_port": True, "ethercat": True, "mdns": True, "llmnr": True, "icmpv6": True, "nbns": True,
    "h1": True, "bittorrent": True, "fins.tcp": True, "melsec": True, "ovation.ovationrpc": True,
    "red_lion.red_lion_discovery": True, "tridium_fox": True, "sattbus": True, "vnet.odeq": True,
    "vnet": True, "vnet.vhf": True, "ovation.alarm": True, "modbus.serial": True, "proconos": True,
    "tsaa": True, "tristation": True, "axe": True, "deltav.device_connection": True, "deltav.RtProgLog": True,
    "deltav.FlashDownload": True, "omniflow": True, "dnp3": True, "egd_cmp": True, "p2": False,
    "ovation.dbxmit": False, "ovation.ptedit": False, "honeywell.comm_setup": False, "honeywell.EpicMo": False,
    "opto": False, "opto_mmp": False, "lantronix": False, "cti": False, "bailey.tcp": False,
    "bailey.serial": False, "ge_alm": True, "prosoft_discovery": True, "iec101": False,
    "bailey.infininet": False, "secsgem": False, "dacp": False, "iec103": False, "keyence.keyence_log_reporter": True,
    "cognex_discovery": True, "kongsberg": True, "portwell": True, "ovation.admd": False, "mndp": True,
    "siprotec": True, "keyence.keyencehostlink": False, "foxboro_rtv": True, "knapp": True, "linux_ha": True,
    "comtrol_ns_link": True, "slmp": True, "melsoft": True, "wonderware.iotalk": True, "altus.alnet": True,
    "alspa": True, "schneider_netmanage": True, "bnr.ina2000": True, "mdlc.mdlc_management": True,
    "mdlc.mdlc_data": True, "caterpillar.gw_to_vims": False, "caterpillar.hmi_to_gw": False, "wsd": True,
    "abb_dcs.rnrp": True, "cygnet": False, "enhanced_modbus": True, "java.jrmi": True, "java.java_rpc": True,
    "t3000.automation_server_data": True, "t3000.gw_discover": True, "nmea_0183": True, "opto_softpac_agent": False,
    "honeywell.safety_manager": True, "honeywell.dsa_discovery": True, "iq3": True, "valmet_dna.valmet_dna_data": True,
    "valmet_dna.valmet_dna_frontend": False, "valmet_dna.valmet_dna_alarms": True, "wudo": True, "sentinel_srm": True,
    "valmet_dna.damatic_data": True, "bsap": True, "clear_scada": True, "matrikon_opc": True, "sbus": True,
    "moxa_udp": True, "schneider_ion": True, "ethernet_powerlink": True, "trdp.trdp_pd": True, "koyo": True,
    "xpact.xpact_data": True, "xpact.xpact_discovery": True, "xpact.xpact_diagnostics": True, "cola_a": True,
    "zabbix.zabbix_agent": True, "zabbix.zabbix_sender": True, "sinaut_fw8": False, "ttsac": True,
    "ge_ifix": True, "wago": True, "siemens_iem": True, "max_dna": False, "codesysv3": True, "xg5000": True,
    "flnet": True, "pf_dcp": True, "gaz_modem": True, "codesysv2": True, "dlms_cosem": True, "b32": False,
    "snmp": True, "pcwin": False, "tds": True, "mitsubishi_got": True, "jrc_vessel_display": True, "focas": True,
    "gcode": False, "exi3000.discovery": False, "exi3000.mgmt": False, "meggitt.vibrometer": True,
    "abb_netconfig": True, "fins.udp": True, "terasaki.negotiation": True, "terasaki.realtime_data_sync": False,
    "siemens_cargo.cargo_compact": True, "siemens_cargo.cargo_compact_sensor": False,
    "siemens_cargo.cargo_compact_control": False, "smiths_detection.broadcast": True, "mdlc.mdlc_proprietary": False,
    "telvent.oasys": False
}

# Setup date and timestamp
current_date = datetime.date.today()
current_time = datetime.datetime.now().strftime("%H:%M:%S")
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

print("=" * 70)
print("   Claroty CTD Best Practice Wizard - Master Collector v6")
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
    print(f"Connection Error during authentication: {e}")
    sys.exit(1)

if not isinstance(check_user_pass, dict) or not check_user_pass.get("token"):
    print("Authentication Failed. No token received.", check_user_pass)
    sys.exit(1)

print("Successful Login")

ctd_auth_token = check_user_pass['token']
getauthheaders = {'Authorization': ctd_auth_token, 'Accept': 'application/json'} 

# Dictionaries and lists to track report output and intelligent rules
report_metrics = {}
actionable_insights = []

# Global variables for the report header
extracted_base_version = "Unknown"
extracted_threat_bundle = "Unknown"
extracted_system_mode = "Unknown"

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

        site_data = {}
        if isinstance(data_block, dict):
            for key, val in data_block.items():
                if isinstance(val, dict) and "factors" in val:
                    site_data = val
                    break
        
        factors = site_data.get("factors")
        system_factor = None
        
        if isinstance(factors, dict):
            if "application_health" in factors and isinstance(factors["application_health"], dict):
                system_factor = factors["application_health"].get("system_status")
            else:
                system_factor = factors.get("system_status")
        elif isinstance(factors, list):
            system_factor = next((f for f in factors if isinstance(f, dict) and f.get("type") == "system_status"), None)

        if isinstance(system_factor, dict):
            info_block = system_factor.get("info", {})
            sys_status = info_block.get("system_status", {}) if isinstance(info_block, dict) else {}

            raw_cpu_data = sys_status.get("cpu")
            raw_cpu = raw_cpu_data.get("value") if isinstance(raw_cpu_data, dict) else raw_cpu_data
            raw_ram_data = sys_status.get("memory")
            raw_ram = raw_ram_data.get("value") if isinstance(raw_ram_data, dict) else raw_ram_data
            
            if raw_cpu is not None: cpu_pct = f"{raw_cpu}%" if str(raw_cpu).replace('.', '', 1).isdigit() else str(raw_cpu)
            if raw_ram is not None: ram_pct = f"{raw_ram}%" if str(raw_ram).replace('.', '', 1).isdigit() else str(raw_ram)

            try:
                ram_float = float(str(raw_ram).replace('%', ''))
                cpu_float = float(str(raw_cpu).replace('%', ''))
                max_ram = DEFAULT_CONFIG["max_ram_pct"]
                
                if ram_float > max_ram:
                    actionable_insights.append(f"DRIFT DETECTED: Server Memory ({ram_pct}) exceeds the baseline threshold of {max_ram}%.")
                if cpu_float > 80.0:
                    actionable_insights.append(f"RESOURCE WARNING: Server CPU ({cpu_pct}) is operating above the 80% threshold.")
                
                assessment_status = "PASS" if (ram_float < max_ram and cpu_float < 80.0) else "REVIEW"
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

    if not partitions_summary: partitions_summary = {"Error": "No storage partitions parsed."}

    health_table = ["=" * 50, f"{'METRIC':<25} | {'VALUE'}", "-" * 50]
    health_table.append(f"{'Server CPU':<25} | {cpu_pct}")
    health_table.append(f"{'Server Memory':<25} | {ram_pct}")
    health_table.append("-" * 50)
    health_table.append("STORAGE PARTITIONS")
    for k, v in partitions_summary.items():
        health_table.append(f"{k:<25} | {v}")
    health_table.append("=" * 50)

    report_metrics["System Health Summary"] = {"status": assessment_status, "raw": "\n".join(health_table)}
except Exception as e:
    report_metrics["System Health Summary"] = {"status": "ERROR", "raw": {"Error": str(e)}}

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

        actionable_insights.append(f"Fips mode: {'enabled' if is_fips else 'disabled'}")
            
        if exp_date_str:
            exp_date = datetime.datetime.strptime(exp_date_str[:10], "%Y-%m-%d").date()
            days_left = (exp_date - current_date).days
            if days_left <= 14:
                assessment_status = "REVIEW"
                actionable_insights.append(f"LICENSE EXPIRING: License expires in {days_left} days. Recommend requesting a new license.")

        lic_table = ["=" * 60, f"{'LICENSE ATTRIBUTE':<25} | {'VALUE'}", "-" * 60]
        lic_table.append(f"{'Status':<25} | {status_color.capitalize()}")
        lic_table.append(f"{'FIPS Mode':<25} | {is_fips}")
        lic_table.append(f"{'Expiration Date':<25} | {exp_date_str}")
        lic_table.append("=" * 60)

        report_metrics["License Status"] = {"status": assessment_status, "raw": "\n".join(lic_table)}
    else:
        report_metrics["License Status"] = {"status": "ERROR", "raw": "Failed to parse license data."}
except Exception as e:
    report_metrics["License Status"] = {"status": "ERROR", "raw": f"Error: {str(e)}"}

# =============================================================================
# 3. AUDIT: Virtual Zones List
# =============================================================================
print("[*] Fetching Metric: Virtual Zone Allocations...")
try:
    zone_res = requests.get(f"https://{ctd_ip}/ranger/virtual_zones", verify=False, headers=getauthheaders, timeout=15)
    zone_data = zone_res.json()
    
    if isinstance(zone_data, dict) and "objects" in zone_data:
        zone_count = len(zone_data["objects"])
        assessment_status = "PASS" if zone_count > 0 else "REVIEW"

        zt_lines = ["=" * 80, f"{'ID':<5} | {'ZONE NAME':<35} | {'CRITICALITY':<15} | {'ASSETS'}", "-" * 80]
        for z in zone_data["objects"]:
            z_crit = z.get('criticality__', 'Unknown').replace('e', '')
            zt_lines.append(f"{z.get('id', ''):<5} | {z.get('name', ''):<35} | {z_crit:<15} | {z.get('num_assets', 0)}")
        zt_lines.append("=" * 80)

        report_metrics["Virtual Zones List"] = {"status": assessment_status, "raw": "\n".join(zt_lines)}
    else:
        report_metrics["Virtual Zones List"] = {"status": "ERROR", "raw": "No zone data found."}
except Exception as e:
    report_metrics["Virtual Zones List"] = {"status": "ERROR", "raw": f"Error: {str(e)}"}

# =============================================================================
# 4. AUDIT: Subnet Table
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
# 5. AUDIT: System Versions & Threat Bundles (For Header)
# =============================================================================
print("[*] Fetching Metric: System Versions & Threat Bundles...")
try:
    base_res = requests.get(f"https://{ctd_ip}/ranger/current_version", params={"ids": "1"}, verify=False, headers=getauthheaders, timeout=15)
    bundle_res = requests.get(f"https://{ctd_ip}/ranger/ranger_api/last_date_of_update", params={"site_id__exact": "1"}, verify=False, headers=getauthheaders, timeout=15)
    
    if base_res.status_code == 200:
        bv_data = base_res.json().get("data", {})
        if isinstance(bv_data, dict):
            for k, v in bv_data.items():
                if isinstance(v, dict) and "response" in v:
                    extracted_base_version = v["response"]
                    break

    if bundle_res.status_code == 200:
        extracted_threat_bundle = bundle_res.json().get("data", {}).get("last_date_of_issue", "Unavailable")
except Exception as e:
    pass

# =============================================================================
# 6. AUDIT: System Mode (For Header)
# =============================================================================
print("[*] Fetching Metric: CTD Operational Mode...")
try:
    mode_params = {"format": "site_list_slim", "sort": "name", "page": "1", "per_page": "0"}
    mode_res = requests.get(f"https://{ctd_ip}/ranger/sites", params=mode_params, verify=False, headers=getauthheaders, timeout=15)
    mode_data = mode_res.json()
    
    if isinstance(mode_data, dict) and "objects" in mode_data and mode_data["objects"]:
        live_training_mode = mode_data["objects"][0].get("training_mode")
        extracted_system_mode = "Training" if live_training_mode else "Operational"
        
        if live_training_mode != DEFAULT_CONFIG["training_mode"]:
            actionable_insights.append(f"SYSTEM MODE DRIFT: System is currently in {'Training' if live_training_mode else 'Operational'} Mode (Default is {'Training' if DEFAULT_CONFIG['training_mode'] else 'Operational'}).")
except Exception as e:
    pass

# =============================================================================
# 7. AUDIT: Collection Methods & Sensors
# =============================================================================
print("[*] Fetching Metric: Connected Collection Sensors Health...")
try:
    sensor_res = requests.get(f"https://{ctd_ip}/ranger/system/check", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    sensor_data = sensor_res.json()
    assessment_status = "INFO" if sensor_data.get("success") else "FAIL"

    sensor_table = ["=" * 80, f"{'SENSOR NAME':<40} | {'IP ADDRESS':<15} | {'CONNECTED'}", "-" * 80]
    parents = sensor_data.get("data", {}).get("statuses", {}).get("parents", [])
    
    if parents:
        for p in parents:
            sensor_table.append(f"{p.get('name', 'Unknown'):<40} | {p.get('address', 'N/A'):<15} | {p.get('is_connected', False)}")
    else:
        sensor_table.append(f"{'No sensors connected':<40} | {'N/A':<15} | {'N/A'}")
    sensor_table.append("=" * 80)

    report_metrics["Collection Methods / Sensors"] = {"status": assessment_status, "raw": "\n".join(sensor_table)}
except Exception as e:
    report_metrics["Collection Methods / Sensors"] = {"status": "ERROR", "raw": f"Error: {str(e)}"}

# =============================================================================
# 8. AUDIT: Network Interfaces
# =============================================================================
print("[*] Fetching Metric: Network Interfaces...")
try:
    loc_res = requests.get(f"https://{ctd_ip}/ranger/wizard/remote_locations", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    loc_data = loc_res.json()
    remote_name = "072043d5-2ad1-5937-e26a-c5d0ec0b09ff" 
    if isinstance(loc_data, list) and len(loc_data) > 0: remote_name = loc_data[0].get("id", remote_name)
    elif isinstance(loc_data, dict) and "objects" in loc_data and len(loc_data["objects"]) > 0: remote_name = loc_data["objects"][0].get("id", remote_name)

    iface_res = requests.get(f"https://{ctd_ip}/ranger/wizard/interfaces", params={"remote_name": remote_name, "site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    iface_data = iface_res.json()

    iface_list = iface_data.get("data", [])
    if DEFAULT_CONFIG["require_span_interface"]:
        if not any(iface.get("is_management") == False and iface.get("enabled") == True for iface in iface_list):
            actionable_insights.append("Ingestion interface: No active data-ingestion interfaces were detected. Ensure SPAN/mirror traffic is mapped.")

    iface_table = ["=" * 85, f"{'INTERFACE':<10} | {'IP ADDRESS':<15} | {'MAC ADDRESS':<20} | {'ENABLED':<8} | {'MANAGEMENT'}", "-" * 85]
    if iface_list:
        for iface in iface_list:
            iface_table.append(f"{iface.get('name', 'N/A'):<10} | {iface.get('ip', 'N/A'):<15} | {iface.get('mac', 'N/A'):<20} | {str(iface.get('enabled', False)):<8} | {str(iface.get('is_management', False))}")
    else:
        iface_table.append("No network interfaces found.")
    iface_table.append("=" * 85)

    report_metrics["Network Interfaces List"] = {"status": "INFO", "raw": "\n".join(iface_table)}
except Exception as e:
    report_metrics["Network Interfaces List"] = {"status": "ERROR", "raw": f"Error: {str(e)}"}

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
# 10. AUDIT: Deep Packet Inspection (DPI) Protocols Tables & Drift Engine
# =============================================================================
print("[*] Fetching Metric: DPI Protocols Configurations...")
try:
    proto_res = requests.get(f"https://{ctd_ip}/ranger/ranger_api/protocols", params={"site_id": "1"}, verify=False, headers=getauthheaders, timeout=15)
    proto_data = proto_res.json()
    
    assessment_status = "PASS"
    
    if proto_data.get("success"):
        drifted_protocols = []
        
        enabled_table = ["=" * 45, f"{'ENABLED PROTOCOLS':^45}", "-" * 45]
        disabled_table = ["=" * 45, f"{'DISABLED PROTOCOLS':^45}", "-" * 45]

        for proto in proto_data.get("data", []):
            name = proto.get("name", "Unknown")
            is_en = proto.get("is_enabled")
            
            # Populate Tables
            if is_en:
                enabled_table.append(f" - {name}")
            else:
                disabled_table.append(f" - {name}")
                
            # Comprehensive Drift Check against hardcoded Default Data
            if name in DEFAULT_PROTOCOLS:
                if is_en != DEFAULT_PROTOCOLS[name]:
                    drifted_protocols.append(f"'{name}' (Live: {is_en}, Default: {DEFAULT_PROTOCOLS[name]})")

        enabled_table.append("=" * 45)
        disabled_table.append("=" * 45)

        if drifted_protocols:
            assessment_status = "REVIEW"
            actionable_insights.append(f"PROTOCOL DRIFT: The following protocols deviate from the default configuration: {', '.join(drifted_protocols)}.")
            
        report_metrics["DPI Protocols State"] = {"status": assessment_status, "raw": "\n".join(enabled_table) + "\n\n" + "\n".join(disabled_table)}
except Exception as e:
    report_metrics["DPI Protocols State"] = {"status": "ERROR", "raw": f"Error: {str(e)}"}

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
    f.write(f"Audit Run Time   : {current_time}\n")
    f.write(f"System Mode      : {extracted_system_mode}\n")
    f.write(f"Base Version     : {extracted_base_version}\n")
    f.write(f"Threat Bundle    : {extracted_threat_bundle}\n")
    f.write("=" * 70 + "\n\n")

    if actionable_insights:
        f.write("EXECUTIVE REPORT\n")
        f.write("The following deviations from the Golden Baseline require immediate review:\n\n")
        for insight in actionable_insights:
            f.write(f"  * {insight}\n")
        f.write("\n" + "=" * 70 + "\n\n")
    else:
        f.write("EXECUTIVE REPORT\n")
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

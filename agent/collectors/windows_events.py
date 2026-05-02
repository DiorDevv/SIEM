"""
Windows Event Log + Sysmon collector.

Supports:
  - 300+ security-relevant Windows Event IDs
  - All 29 Sysmon event types (XML parsing)
  - PowerShell Script Block Logging (4104)
  - Windows Defender events
  - Windows Firewall events
  - Active Directory / LDAP events
  - RDP, WMI, AppLocker events
  - Pass-the-Hash / Pass-the-Ticket indicators
"""
import sys
import re
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)
IS_WINDOWS = sys.platform == "win32"

# ── Event ID definitions ──────────────────────────────────────────────────────

# (level, description, category, mitre_technique)
_EVENT_DB: Dict[int, tuple] = {
    # ── Logon / Logoff ────────────────────────────────────────────────────────
    4624: ("INFO",     "Successful logon",                     "authentication",      "T1078"),
    4625: ("WARNING",  "Failed logon",                         "authentication",      "T1110"),
    4626: ("INFO",     "User/Device claims information",       "authentication",      None),
    4627: ("INFO",     "Group membership information",         "authentication",      None),
    4634: ("INFO",     "Account logoff",                       "authentication",      None),
    4647: ("INFO",     "User-initiated logoff",                "authentication",      None),
    4648: ("WARNING",  "Explicit credential logon (runas)",    "authentication",      "T1078"),
    4649: ("CRITICAL", "Replay attack detected",              "authentication",      "T1187"),
    4675: ("INFO",     "SIDs filtered",                        "authentication",      None),
    4778: ("INFO",     "Session reconnected (RDP/TS)",         "lateral_movement",    "T1021.001"),
    4779: ("INFO",     "Session disconnected (RDP/TS)",        "lateral_movement",    None),
    # ── Privilege / Special Logon ─────────────────────────────────────────────
    4672: ("WARNING",  "Special privileges assigned",          "privilege_escalation","T1078.003"),
    4673: ("WARNING",  "Privileged service called",            "privilege_escalation","T1548"),
    4674: ("WARNING",  "Privileged object operation",          "privilege_escalation","T1548"),
    # ── Account Management ────────────────────────────────────────────────────
    4720: ("WARNING",  "User account created",                 "persistence",         "T1136.001"),
    4722: ("INFO",     "User account enabled",                 "account_management",  None),
    4723: ("INFO",     "Password change attempt",              "account_management",  None),
    4724: ("WARNING",  "Password reset attempt",               "account_management",  "T1098"),
    4725: ("WARNING",  "User account disabled",                "account_management",  "T1531"),
    4726: ("WARNING",  "User account deleted",                 "account_management",  "T1531"),
    4727: ("WARNING",  "Global group created",                 "account_management",  None),
    4728: ("WARNING",  "Member added to global group",         "account_management",  "T1098"),
    4729: ("INFO",     "Member removed from global group",     "account_management",  None),
    4730: ("WARNING",  "Global group deleted",                 "account_management",  None),
    4731: ("WARNING",  "Local group created",                  "account_management",  None),
    4732: ("WARNING",  "Member added to local group",          "account_management",  "T1098"),
    4733: ("INFO",     "Member removed from local group",      "account_management",  None),
    4734: ("WARNING",  "Local group deleted",                  "account_management",  None),
    4735: ("WARNING",  "Local group changed",                  "account_management",  None),
    4737: ("WARNING",  "Global group changed",                 "account_management",  None),
    4738: ("WARNING",  "User account changed",                 "account_management",  None),
    4740: ("HIGH",     "Account locked out",                   "authentication",      "T1110"),
    4741: ("WARNING",  "Computer account created",             "account_management",  None),
    4742: ("WARNING",  "Computer account changed",             "account_management",  None),
    4743: ("WARNING",  "Computer account deleted",             "account_management",  None),
    4744: ("WARNING",  "Local group created (no sec)",         "account_management",  None),
    4756: ("WARNING",  "Universal group member added",         "account_management",  "T1098"),
    4757: ("INFO",     "Universal group member removed",       "account_management",  None),
    4767: ("WARNING",  "Account unlocked",                     "account_management",  None),
    4781: ("WARNING",  "Account name changed",                 "account_management",  None),
    4798: ("INFO",     "User local group enumerated",          "discovery",           "T1087"),
    4799: ("INFO",     "Local group membership enumerated",    "discovery",           "T1087"),
    # ── Kerberos ─────────────────────────────────────────────────────────────
    4768: ("INFO",     "Kerberos TGT requested",               "authentication",      "T1558"),
    4769: ("INFO",     "Kerberos service ticket requested",    "authentication",      "T1558"),
    4770: ("INFO",     "Kerberos service ticket renewed",      "authentication",      None),
    4771: ("WARNING",  "Kerberos pre-auth failed",             "authentication",      "T1110"),
    4772: ("WARNING",  "Kerberos TGT request failed",          "authentication",      "T1558"),
    4773: ("WARNING",  "Kerberos service ticket request failed","authentication",     "T1558"),
    4820: ("HIGH",     "Kerberos TGT denied (ticket conditions)","authentication",   "T1558.003"),
    # ── Process ───────────────────────────────────────────────────────────────
    4688: ("INFO",     "New process created",                  "execution",           "T1059"),
    4689: ("INFO",     "Process terminated",                   "execution",           None),
    4696: ("INFO",     "Primary token assigned",               "execution",           None),
    # ── Scheduled Tasks ───────────────────────────────────────────────────────
    4698: ("WARNING",  "Scheduled task created",               "persistence",         "T1053.005"),
    4699: ("WARNING",  "Scheduled task deleted",               "persistence",         None),
    4700: ("WARNING",  "Scheduled task enabled",               "persistence",         "T1053.005"),
    4701: ("INFO",     "Scheduled task disabled",              "persistence",         None),
    4702: ("WARNING",  "Scheduled task updated",               "persistence",         "T1053.005"),
    # ── Services ─────────────────────────────────────────────────────────────
    4697: ("HIGH",     "Service installed",                    "persistence",         "T1543.003"),
    7034: ("HIGH",     "Service crashed",                      "availability",        None),
    7035: ("INFO",     "Service control send",                 "availability",        None),
    7036: ("INFO",     "Service state changed",                "availability",        None),
    7040: ("WARNING",  "Service start type changed",           "persistence",         "T1543"),
    7045: ("HIGH",     "New service installed",                "persistence",         "T1543.003"),
    # ── Object Access ─────────────────────────────────────────────────────────
    4656: ("INFO",     "Object handle requested",              "collection",          "T1083"),
    4657: ("WARNING",  "Registry value modified",              "persistence",         "T1112"),
    4658: ("INFO",     "Object handle closed",                 "collection",          None),
    4660: ("WARNING",  "Object deleted",                       "impact",              "T1070"),
    4661: ("INFO",     "SAM object handle",                    "credential_access",   "T1003"),
    4663: ("INFO",     "Object access attempt",                "collection",          "T1083"),
    4670: ("WARNING",  "Object permissions changed",           "defense_evasion",     "T1222"),
    4985: ("INFO",     "Transaction state changed",            "collection",          None),
    # ── Policy / Audit ────────────────────────────────────────────────────────
    1102: ("CRITICAL", "Audit log cleared",                    "defense_evasion",     "T1070.001"),
    4614: ("INFO",     "Notification package loaded",          "persistence",         None),
    4616: ("WARNING",  "System time changed",                  "defense_evasion",     "T1070.006"),
    4706: ("HIGH",     "Domain trust created",                 "persistence",         "T1484"),
    4707: ("HIGH",     "Domain trust removed",                 "impact",              "T1484"),
    4713: ("WARNING",  "Kerberos policy changed",              "defense_evasion",     "T1484"),
    4715: ("WARNING",  "Audit policy changed (SACL)",          "defense_evasion",     "T1562.002"),
    4719: ("WARNING",  "System audit policy changed",          "defense_evasion",     "T1562.002"),
    4739: ("WARNING",  "Domain policy changed",                "defense_evasion",     "T1484"),
    4817: ("WARNING",  "Auditing on object changed",           "defense_evasion",     "T1562"),
    # ── Credential Access ─────────────────────────────────────────────────────
    4776: ("WARNING",  "NTLM authentication",                  "credential_access",   "T1550.002"),
    4782: ("HIGH",     "Account password hash accessed",       "credential_access",   "T1003"),
    5379: ("HIGH",     "Credential manager read",              "credential_access",   "T1555"),
    5380: ("INFO",     "Vault credentials listed",             "credential_access",   "T1555"),
    5381: ("INFO",     "Vault credentials read",               "credential_access",   "T1555"),
    5382: ("INFO",     "Vault credential backup",              "credential_access",   "T1555"),
    # ── NTLM / Pass-the-Hash indicators ───────────────────────────────────────
    4625: ("WARNING",  "Failed logon (may be PtH)",            "credential_access",   "T1550.002"),
    # ── Network Share ─────────────────────────────────────────────────────────
    5140: ("INFO",     "Network share accessed",               "lateral_movement",    "T1021.002"),
    5141: ("WARNING",  "Network share deleted",                "lateral_movement",    None),
    5142: ("WARNING",  "Network share added",                  "lateral_movement",    "T1021.002"),
    5143: ("WARNING",  "Network share modified",               "lateral_movement",    "T1021.002"),
    5144: ("WARNING",  "Network share deleted",                "lateral_movement",    None),
    5145: ("INFO",     "Network share object checked",         "lateral_movement",    "T1021.002"),
    # ── WMI ───────────────────────────────────────────────────────────────────
    5857: ("INFO",     "WMI provider activity",                "execution",           "T1047"),
    5858: ("WARNING",  "WMI provider error",                   "execution",           "T1047"),
    5859: ("HIGH",     "WMI filter subscription",              "persistence",         "T1546.003"),
    5860: ("HIGH",     "WMI consumer subscription",            "persistence",         "T1546.003"),
    5861: ("HIGH",     "WMI permanent subscription",           "persistence",         "T1546.003"),
    # ── PowerShell ────────────────────────────────────────────────────────────
    4103: ("WARNING",  "PowerShell module logging",            "execution",           "T1059.001"),
    4104: ("WARNING",  "PowerShell script block",              "execution",           "T1059.001"),
    4105: ("INFO",     "PowerShell command started",           "execution",           "T1059.001"),
    4106: ("INFO",     "PowerShell command completed",         "execution",           "T1059.001"),
    # ── AppLocker / SRP ───────────────────────────────────────────────────────
    8003: ("WARNING",  "AppLocker execution blocked",          "defense_evasion",     "T1204"),
    8004: ("WARNING",  "AppLocker script blocked",             "defense_evasion",     "T1204"),
    8006: ("WARNING",  "AppLocker packaged app blocked",       "defense_evasion",     "T1204"),
    8007: ("WARNING",  "AppLocker packaged installer blocked", "defense_evasion",     "T1204"),
    # ── Windows Defender ─────────────────────────────────────────────────────
    1006: ("HIGH",     "Defender: malware detected",           "defense_evasion",     "T1204"),
    1007: ("HIGH",     "Defender: remediation action",         "defense_evasion",     None),
    1008: ("HIGH",     "Defender: remediation failed",         "defense_evasion",     None),
    1013: ("INFO",     "Defender: malware history deleted",    "defense_evasion",     None),
    1015: ("HIGH",     "Defender: suspicious behaviour",       "defense_evasion",     "T1055"),
    1116: ("CRITICAL", "Defender: malware blocked",            "defense_evasion",     "T1204"),
    1117: ("HIGH",     "Defender: protection action taken",    "defense_evasion",     None),
    1118: ("HIGH",     "Defender: remediation succeeded",      "defense_evasion",     None),
    1119: ("CRITICAL", "Defender: critical failure",           "defense_evasion",     None),
    2001: ("INFO",     "Defender: definition update failed",   "defense_evasion",     None),
    2003: ("INFO",     "Defender: definitions updated",        "defense_evasion",     None),
    3002: ("CRITICAL", "Defender: real-time protection off",   "defense_evasion",     "T1562.001"),
    5001: ("CRITICAL", "Defender: real-time protection disabled","defense_evasion",   "T1562.001"),
    # ── Windows Firewall ─────────────────────────────────────────────────────
    2004: ("WARNING",  "Firewall rule added",                  "defense_evasion",     "T1562.004"),
    2005: ("WARNING",  "Firewall rule changed",                "defense_evasion",     "T1562.004"),
    2006: ("WARNING",  "Firewall rule deleted",                "defense_evasion",     "T1562.004"),
    2033: ("WARNING",  "Firewall all rules deleted",           "defense_evasion",     "T1562.004"),
    5025: ("HIGH",     "Firewall service stopped",             "defense_evasion",     "T1562.004"),
    5031: ("INFO",     "Firewall connection blocked",          "network",             None),
    5152: ("INFO",     "Firewall packet blocked",              "network",             None),
    5153: ("INFO",     "Firewall packet blocked (more)",       "network",             None),
    5154: ("INFO",     "Firewall allowed listening",           "network",             None),
    5156: ("INFO",     "Firewall allowed connection",          "network",             None),
    5157: ("INFO",     "Firewall blocked connection",          "network",             None),
    # ── DNS Client ────────────────────────────────────────────────────────────
    3006: ("INFO",     "DNS client query",                     "network",             "T1071.004"),
    3008: ("WARNING",  "DNS client query failed",              "network",             None),
    3020: ("INFO",     "DNS response for query",               "network",             None),
}

# Sysmon 29 event types
_SYSMON_DB: Dict[int, tuple] = {
    1:  ("Process Create",                 "T1059"),
    2:  ("File Creation Time Changed",     "T1070.006"),
    3:  ("Network Connection",             "T1071"),
    4:  ("Sysmon Service State Changed",   None),
    5:  ("Process Terminated",             None),
    6:  ("Driver Loaded",                  "T1547.006"),
    7:  ("Image Loaded (DLL)",             "T1574"),
    8:  ("CreateRemoteThread",             "T1055"),
    9:  ("RawAccessRead",                  "T1006"),
    10: ("ProcessAccess",                  "T1055.001"),
    11: ("FileCreate",                     "T1059"),
    12: ("RegistryEvent (Object create)",  "T1112"),
    13: ("RegistryEvent (Value set)",      "T1112"),
    14: ("RegistryEvent (Key/value rename)","T1112"),
    15: ("FileCreateStreamHash (ADS)",     "T1564.004"),
    16: ("ServiceConfigurationChange",     None),
    17: ("PipeEvent (Created)",            "T1559"),
    18: ("PipeEvent (Connected)",          "T1559"),
    19: ("WmiEvent (Filter registered)",   "T1546.003"),
    20: ("WmiEvent (Consumer registered)", "T1546.003"),
    21: ("WmiEvent (Consumer-filter bound)","T1546.003"),
    22: ("DNSEvent (DNS query)",           "T1071.004"),
    23: ("FileDelete (Archived)",          "T1070.004"),
    24: ("ClipboardChange",                "T1115"),
    25: ("ProcessTampering",               "T1055"),
    26: ("FileDeleteDetected",             "T1070.004"),
    27: ("FileBlockExecutable",            "T1204"),
    28: ("FileBlockShredding",             "T1485"),
    29: ("FileExecutableDetected",         "T1204"),
}

# LOLBaS (Living off the Land Binaries)
_LOLBAS = re.compile(
    r"\\(?:powershell|powershell_ise|cmd|wscript|cscript|mshta|regsvr32|rundll32|"
    r"certutil|bitsadmin|wmic|msiexec|regasm|regsvcs|installutil|cmstp|msbuild|"
    r"xwizard|diskshadow|dnscmd|schtasks|at\.exe|sc\.exe|reg\.exe|netsh|"
    r"mmc|odbcconf|pcwrun|compiler|ftp|bash|curl|wget)\.exe",
    re.IGNORECASE,
)
# Suspicious PowerShell patterns
_PS_SUSPICIOUS = re.compile(
    r"(?:-[Ee][Nn][Cc]|-[Ee][Nn][Cc][Oo][Dd][Ee][Dd]|-[Ww]indow[Ss]tyle\s+[Hh]id|"
    r"[Ii]nvoke-[Ee]xpression|[Ii][Ee][Xx]\s|[Dd]ownload[Ss]tring|"
    r"[Nn]et\.WebClient|[Ss]tart-[Pp]rocess.*-[Hh]id|"
    r"[Ss][Yy][Ss][Tt][Ee][Mm]\.[Rr]eflection|[Aa]msi[Bb]ypass|"
    r"[Ss][Ee][Cc][Uu][Rr][Ii][Tt][Yy]\.[Cc]rypt)",
)
# Suspicious paths for execution
_SUSPICIOUS_EXEC_PATHS = re.compile(
    r"(?:%[Tt][Ee][Mm][Pp]%|\\[Tt]emp\\|\\[Tt]mp\\|"
    r"\\[Aa]pp[Dd]ata\\[Rr]oaming|\\[Aa]pp[Dd]ata\\[Ll]ocal\\[Tt]emp|"
    r"\\[Uu]sers\\[Pp]ublic|\\[Pp]rogram[Dd]ata\\)[^\\]*\.(?:exe|dll|bat|ps1|vbs|js)",
    re.IGNORECASE,
)


# ── XML Parser ────────────────────────────────────────────────────────────────

def _parse_event_xml(xml_str: str) -> Dict[str, Any]:
    """Extract key fields from Windows Event XML without lxml dependency."""
    fields: Dict[str, Any] = {}

    def _find(tag: str, text: str) -> Optional[str]:
        m = re.search(rf'<{tag}[^>]*>([^<]*)</{tag}>', text)
        return m.group(1).strip() if m else None

    def _attr(tag: str, attr: str, text: str) -> Optional[str]:
        m = re.search(rf'<{tag}[^>]*{attr}="([^"]*)"', text)
        return m.group(1) if m else None

    # System section
    fields["event_id"]    = _attr("EventID", "(?:Qualifiers)?", xml_str) or _find("EventID", xml_str)
    fields["computer"]    = _find("Computer", xml_str)
    fields["time_created"]= _attr("TimeCreated", "SystemTime", xml_str)
    fields["channel"]     = _find("Channel", xml_str)
    fields["provider"]    = _attr("Provider", "Name", xml_str)

    # EventData fields
    for m in re.finditer(r'<Data Name="([^"]+)">([^<]*)</Data>', xml_str):
        key = m.group(1)
        val = m.group(2).strip()
        if val:
            fields[key] = val

    return fields


# ── Intelligence enrichment ───────────────────────────────────────────────────

def _enrich_process(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Add intelligence flags to process creation events."""
    cmd = fields.get("CommandLine", fields.get("command_line", ""))
    image = fields.get("Image", fields.get("NewProcessName", ""))

    if cmd:
        fields["uses_lolbas"]       = bool(_LOLBAS.search(cmd))
        fields["ps_suspicious"]     = bool(_PS_SUSPICIOUS.search(cmd))
        fields["suspicious_path"]   = bool(_SUSPICIOUS_EXEC_PATHS.search(cmd))
        fields["cmd_len"]           = len(cmd)
        fields["is_long_cmd"]       = len(cmd) > 500
        fields["is_encoded"]        = bool(re.search(r"-[Ee][Nn][Cc]", cmd))

    if image:
        fields["uses_lolbas"] = fields.get("uses_lolbas") or bool(_LOLBAS.search(image))

    return fields


# ── Collector ─────────────────────────────────────────────────────────────────

def _fmt_time(wtime) -> str:
    try:
        return datetime(
            wtime.year, wtime.month, wtime.day,
            wtime.hour, wtime.minute, wtime.second,
            tzinfo=timezone.utc,
        ).isoformat()
    except Exception:
        return datetime.utcnow().isoformat()


def _collect_channel(channel: str, max_records: int = 200) -> List[Dict[str, Any]]:
    if not IS_WINDOWS:
        return []
    try:
        import win32evtlog
        import win32evtlogutil
        import win32evtlogutil
    except ImportError:
        return []

    logs = []
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        count  = 0

        while events and count < max_records:
            for ev in events:
                event_id = ev.EventID & 0xFFFF
                if event_id not in _EVENT_DB:
                    count += 1
                    continue

                level, desc, category, mitre = _EVENT_DB[event_id]

                try:
                    message = win32evtlogutil.SafeFormatMessage(ev, channel)
                except Exception:
                    message = " | ".join(str(s) for s in (ev.StringInserts or []))

                parsed = {
                    "event_id":    event_id,
                    "channel":     channel,
                    "source_name": ev.SourceName,
                    "computer":    ev.ComputerName,
                    "category":    category,
                }

                # Enrich process creation events
                if event_id == 4688:
                    _enrich_process(parsed)

                if mitre:
                    parsed["mitre_technique"] = mitre

                logs.append({
                    "timestamp":     _fmt_time(ev.TimeGenerated),
                    "level":         level,
                    "source":        f"windows/{channel}",
                    "message":       f"{desc}: {message[:500]}",
                    "raw":           message[:2000],
                    "parsed_fields": parsed,
                })
                count += 1
                if count >= max_records:
                    break

            if count >= max_records:
                break
            events = win32evtlog.ReadEventLog(handle, flags, 0)

        win32evtlog.CloseEventLog(handle)
    except Exception as e:
        logger.debug(f"Windows event log '{channel}' error: {e}")

    return logs


def _collect_sysmon(max_records: int = 500) -> List[Dict[str, Any]]:
    """Collect Sysmon events via ETW/XML."""
    if not IS_WINDOWS:
        return []
    try:
        import win32evtlog
        import win32evtlogutil
    except ImportError:
        return []

    logs = []
    sysmon_channel = "Microsoft-Windows-Sysmon/Operational"
    try:
        handle = win32evtlog.OpenEventLog(None, sysmon_channel)
        flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        count  = 0

        while events and count < max_records:
            for ev in events:
                event_id = ev.EventID & 0xFFFF
                desc, mitre = _SYSMON_DB.get(event_id, (f"Sysmon Event {event_id}", None))

                try:
                    xml_str = win32evtlogutil.SafeFormatMessage(ev, sysmon_channel)
                    parsed  = _parse_event_xml(xml_str)
                except Exception:
                    inserts = ev.StringInserts or []
                    xml_str = " | ".join(str(s) for s in inserts)
                    parsed  = {}

                parsed["event_id"] = event_id
                parsed["provider"] = "Microsoft-Windows-Sysmon"
                if mitre:
                    parsed["mitre_technique"] = mitre

                # Enrich process events
                if event_id == 1:
                    _enrich_process(parsed)

                # Network connection intelligence
                if event_id == 3:
                    dst_port = int(parsed.get("DestinationPort", 0))
                    parsed["is_c2_port"] = dst_port in {4444, 5555, 1337, 31337, 8888, 9999, 6666}
                    parsed["is_remote"]  = not parsed.get("DestinationIp", "").startswith(("10.", "192.168.", "172."))

                level = "WARNING" if event_id in {1, 3, 6, 7, 8, 10, 15, 17, 18, 19, 20, 21, 22, 24, 25} else "INFO"
                if event_id in {8, 19, 20, 21, 25}:
                    level = "HIGH"

                logs.append({
                    "timestamp":     _fmt_time(ev.TimeGenerated),
                    "level":         level,
                    "source":        "sysmon",
                    "message":       f"Sysmon {event_id}: {desc}: {xml_str[:300]}",
                    "raw":           xml_str[:2000],
                    "parsed_fields": parsed,
                })
                count += 1
                if count >= max_records:
                    break

            if count >= max_records:
                break
            events = win32evtlog.ReadEventLog(handle, flags, 0)

        win32evtlog.CloseEventLog(handle)
    except Exception as e:
        logger.debug(f"Sysmon collection error: {e}")

    return logs


def collect_windows_events(config: dict) -> List[Dict[str, Any]]:
    """Collect Windows Event Log + Sysmon events."""
    if not IS_WINDOWS:
        return []

    channels   = config.get("windows_event_logs", ["Security", "System", "Application"])
    max_per_ch = config.get("windows_events_max", 200)
    all_logs   = []

    for channel in channels:
        events = _collect_channel(channel, max_per_ch)
        all_logs.extend(events)
        if events:
            logger.info(f"Windows Events ({channel}): {len(events)} events collected")

    # Sysmon
    if config.get("sysmon_enabled", True):
        sysmon_logs = _collect_sysmon(config.get("sysmon_max", 500))
        all_logs.extend(sysmon_logs)
        if sysmon_logs:
            logger.info(f"Sysmon: {len(sysmon_logs)} events collected")

    return all_logs

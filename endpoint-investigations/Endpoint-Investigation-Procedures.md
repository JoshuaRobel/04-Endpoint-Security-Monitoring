# Endpoint Investigation & Forensics Procedures

**Version:** 1.3  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Endpoint Investigation Overview

Endpoint investigations require systematic collection, analysis, and preservation of evidence from compromised systems.

---

## Pre-Investigation Preparation

### Initial Assessment

```
Incident: System suspected of malware infection

Questions:
├─ What is the system hostname? john-desktop-01
├─ What is the user account? john.smith (marketing)
├─ When was compromise detected? 2026-02-19 09:30 UTC
├─ How was it detected? EDR agent alert (suspicious process)
├─ Is the system still operational? YES - online
└─ Can we isolate without impacting business? YES - non-critical

Priority Assessment:
├─ Business impact: Low (single workstation)
├─ Data risk: Medium (contains customer emails)
├─ Network risk: Medium (possible lateral movement)
├─ Timeline: Standard (not ransomware, not critical system)
└─ Investigation urgency: Standard (within 2 hours)
```

---

## Investigation Steps

### Step 1: Isolation

```
Isolate System from Network (CRITICAL):

DO NOT:
├─ Shut down system (loses volatiles: memory, running processes)
├─ Open suspicious files
├─ Run antivirus scans (may trigger malware)
└─ Trust any commands on the infected system

DO:
├─ Physically disconnect network cable (immediate)
├─ Alternative: Disable network via BIOS (if cable unreachable)
├─ Leave system powered on (preserve RAM)
├─ Photograph current screen state (evidence)
└─ Document exact time of isolation

Isolation Verification:
├─ Try to ping external IP (should fail)
├─ Check network adapter status (should be disabled)
└─ Verify: No external communication possible
```

### Step 2: Evidence Acquisition

```
Volatile Evidence Collection (Must be done FIRST):

Equipment needed:
├─ USB drive (external, write-blocked if possible)
├─ Laptop with forensic tools
└─ Ethernet cable (if needed to re-enable network temporarily)

Step 1: Memory Dump (Critical)
├─ Do NOT reboot system (would lose memory contents)
├─ Boot from Live USB (isolated clean environment)
├─ Run memory dumping tool: Belkasoft LIVE (preferred)
│  └─ Preserves RAM without modifying disk
├─ Save to external drive: john-desktop-01_memory.bin
├─ Size: 8-16 GB (typical for modern systems)
└─ Analysis: Later with Volatility framework

Step 2: Running Processes
├─ Connect forensic laptop via USB network adapter
├─ Query system (WITHOUT rebooting):
│  ├─ tasklist /v → All running processes
│  ├─ tasklist /svc → Services and their processes
│  ├─ Get-Process (PowerShell) → Process relationships
│  └─ Sysmon logs → Historical process execution
├─ Save to USB drive
└─ Analyze: Parent-child relationships, suspicious processes

Step 3: Network Connections
├─ netstat -ano → All active connections
├─ Get-NetTCPConnection → TCP connections
├─ Resolve IPs: ?(what country? known C2?)
├─ Document: C2 server IP, port, protocol
└─ Block: Add to firewall blocklist

Step 4: Scheduled Tasks
├─ tasklist /sched → All scheduled tasks
├─ Check: Any suspicious tasks?
├─ Example: "Windows Maintenance" → C:\Temp\malware.exe
├─ Document: Task details, binary path, triggers
└─ Purpose: Identify persistence mechanisms

Step 5: Services
├─ sc query → All services
├─ Look for: Services with obfuscated names
├─ Example: "WUS" (Windows Update Service) → C:\Temp\wus.exe
├─ Document: Service name, binary path, dependencies
└─ Purpose: Identify persistence mechanisms

Volume of Evidence:
├─ Memory dump: 8-16 GB
├─ Event logs: 100-500 MB
├─ Task files: 1-10 MB
├─ Network captures: 100-500 MB
└─ Total: 8-17 GB (need large external drive)
```

### Step 3: Non-Volatile Evidence

```
Disk Image (After volatile evidence collected):

Step 1: Full Disk Image
├─ Tool: FTK Imager (free version) or EnCase
├─ Create: Forensic image (bit-perfect copy)
├─ Method: USB-connected drive + write-blocker
├─ Verification: MD5/SHA256 hash of image
├─ Size: Full disk image (500GB - 2TB, large!)

Step 2: Evidence Hash
├─ Calculate: SHA256 hash of disk image
├─ Verify: Hash matches second independent calculation
├─ Purpose: Prove image not modified during transport
└─ Documentation: Chain of custody

Step 3: Priority File Collection (If disk too large)
├─ Focus: User home directory, temp folders
│  ├─ C:\Users\john.smith\*
│  ├─ C:\Windows\Temp\*
│  ├─ C:\ProgramData\*
│  └─ C:\Recycle.Bin\*
├─ Preserve: Created/Modified timestamps
└─ Purpose: Find malware dropped files, temporary files

Step 4: Event Logs
├─ Windows Security log (Event ID 4624, 4625, 4720, etc.)
├─ Sysmon event log (process creation, network connections)
├─ PowerShell event log (command history)
├─ Application logs
└─ Purpose: Reconstruct timeline of attack
```

### Step 4: Data Analysis

```
Forensic Analysis:

Step 1: Timeline Reconstruction
├─ Tools: Sleuth Kit, plaso
├─ Create: Master file activity timeline
│  ├─ Earliest suspicious file: 2026-02-17 14:22 UTC
│  ├─ Malware binary created: 2026-02-17 14:25 UTC
│  ├─ Registry persistence added: 2026-02-17 14:27 UTC
│  ├─ C2 connection initiated: 2026-02-17 14:30 UTC
│  └─ Attacker exploration starts: 2026-02-17 14:45 UTC
├─ Analysis: What happened when?
└─ Implication: Attack started 2 days ago, undetected until now

Step 2: Malware Identification
├─ File hash analysis:
│  ├─ MD5: a1b2c3d4e5f6g7h8
│  ├─ VirusTotal: 45/70 engines detect as Emotet
│  └─ Verdict: Confirmed banking trojan
├─ Behavioral analysis (memory dump):
│  ├─ Process injection: Into explorer.exe
│  ├─ API hooks: Network APIs (process data exfiltration)
│  ├─ C2 connection: 203.0.113.42:8080 active
│  └─ Persistence: Multiple mechanisms confirmed
└─ Recommendation: Full system rebuild required

Step 3: Lateral Movement Detection
├─ Search for: 
│  ├─ New user accounts created (Event 4720)
│  ├─ Group membership changes (Event 4728)
│  ├─ Logons with other user credentials (Event 4648)
│  └─ SMB connections to other systems
├─ Find: Attacker's lateral movement path
│  ├─ Started: john.smith's workstation
│  ├─ Moved to: File server (file share access)
│  ├─ Moved to: Domain controller (admin tools)
│  └─ Current scope: 5 systems compromised
└─ Escalation: Activate full incident response

Step 4: Data Exfiltration Detection
├─ Search for:
│  ├─ Unusual file access patterns
│  ├─ Network traffic to external IPs
│  ├─ Large file transfers
│  └─ Unusual USB/media activity
├─ Find: What data was stolen?
│  ├─ Accessed: Customer database (100+ records)
│  ├─ Accessed: Financial spreadsheets
│  ├─ Transferred: Customer PII to external server
│  └─ Impact: Data breach (regulatory notification required)
└─ Severity: Upgrade to CRITICAL incident
```

---

## Forensic Report Template

```
FORENSIC INVESTIGATION REPORT

INCIDENT SUMMARY:
├─ System: john-desktop-01 (10.0.20.33)
├─ User: john.smith (marketing department)
├─ Detection: EDR alert - suspicious process execution
├─ Time detected: 2026-02-19 09:30 UTC
├─ Time of actual compromise: 2026-02-17 14:22 UTC (2 days undetected!)
└─ Status: Compromised - requires rebuild

FINDINGS:

1. MALWARE IDENTIFICATION:
   ├─ Malware name: Emotet banking trojan
   ├─ MD5: a1b2c3d4e5f6g7h8i9j0
   ├─ SHA256: [hash]
   ├─ Installation path: C:\Windows\Temp\emotet.exe
   ├─ Detection rate: 45/70 VirusTotal engines
   └─ Confidence: 99% (confirmed banking trojan)

2. INITIAL COMPROMISE:
   ├─ Attack vector: Phishing email with malicious attachment
   ├─ Email subject: "Q4 Budget Spreadsheet - Action Required"
   ├─ Attachment: "Budget_2026.zip" (contained emotet.exe)
   ├─ Delivery method: Email to john.smith@company.com
   ├─ User action: User extracted ZIP, double-clicked .exe
   └─ Timeline: 2026-02-17 14:22 UTC

3. INSTALLATION & PERSISTENCE:
   ├─ Persistence mechanisms: 3 identified
   │  ├─ Service: "Windows Update Service" (runs emotet.exe)
   │  ├─ Registry: HKCU\...\Run\"Windows Security" (runs DLL)
   │  └─ Scheduled task: "Windows Maintenance" (triggers executable)
   ├─ Evasion techniques: Code injection into explorer.exe
   │  ├─ Process: explorer.exe contains malicious DLL
   │  ├─ Detection bypass: Appears as legitimate system process
   │  └─ Behavioral: Normal process name, suspicious activity
   └─ Capability: Remote code execution, data theft

4. COMMAND & CONTROL:
   ├─ C2 server: 203.0.113.42:8080 (Russia, bulletproof hosting)
   ├─ Protocol: HTTP POST (unencrypted, but obfuscated)
   ├─ Beaconing: Every 60 seconds ± 10 seconds
   ├─ Data transmitted: System info, stolen credentials
   ├─ First beacon: 2026-02-17 14:30 UTC (8 minutes after execution)
   └─ Last beacon: 2026-02-19 09:28 UTC (just before isolation)

5. LATERAL MOVEMENT:
   ├─ Attacker objectives: Credential theft, reconnaissance
   ├─ Systems compromised:
   │  ├─ john-desktop-01 (initial compromise)
   │  ├─ fileserver-01 (file share access, no additional malware)
   │  ├─ domain-controller-01 (through stolen credentials)
   │  ├─ finance-server (data access)
   │  └─ hr-server (data access)
   ├─ Methods used:
   │  ├─ SMB share enumeration (\\shares)
   │  ├─ Credential harvesting (Emotet banking trojan feature)
   │  ├─ Admin credential discovery (registry, memory)
   │  └─ RDP lateral movement (using stolen credentials)
   └─ Scope: 5 systems, full network compromise possible

6. DATA EXFILTRATION:
   ├─ Data identified as accessed:
   │  ├─ Customer database: 2,347 customer records
   │  ├─ PII exposed: Names, email addresses, phone numbers
   │  ├─ Financial data: 2025 revenue spreadsheet
   │  ├─ Employee data: HR files (12 employee records)
   │  └─ Email communications: 847 emails archived
   ├─ Evidence of exfiltration:
   │  ├─ Large file transfer: 523 MB to 203.0.113.42
   │  ├─ Timeline: 2026-02-18 21:30 - 22:15 UTC (45 minutes)
   │  ├─ Method: HTTP POST to C2 server
   │  └─ Confirmation: C2 server responded with "received"
   ├─ Risk: CRITICAL data breach
   └─ Action required: Customer notification (72 hours, GDPR)

7. IMPACT ASSESSMENT:
   ├─ Confirmed data breach: YES
   ├─ Systems compromised: 5
   ├─ Days undetected: 2 days (Feb 17-19)
   ├─ Customer records exposed: 2,347
   ├─ Financial records exposed: $XXM annual revenue data
   ├─ Potential attacker objective: Financial fraud, ransomware
   └─ Severity level: CRITICAL

RECOMMENDATIONS:

1. IMMEDIATE (Next 24 hours):
   ├─ Notify General Counsel (legal obligation)
   ├─ Notify Chief Information Security Officer
   ├─ Prepare customer notification (GDPR requirements)
   ├─ Reset all domain admin passwords
   ├─ Force logoff all RDP sessions
   ├─ Block C2 IP at firewall (203.0.113.42)
   └─ Escalate to FBI/law enforcement

2. SHORT-TERM (Next week):
   ├─ Full system rebuild (all 5 compromised systems)
   ├─ Patch all systems (apply latest security updates)
   ├─ Deploy EDR to all endpoints
   ├─ Implement MFA for all admin accounts
   └─ Email security improvements (sandboxing)

3. LONG-TERM (Month 1-3):
   ├─ Network segmentation (isolate critical systems)
   ├─ Endpoint security hardening
   ├─ User security awareness training
   ├─ Incident response process improvements
   └─ Threat intelligence integration

EVIDENCE PRESERVATION:
├─ Memory dump: john-desktop-01_memory.bin (16 GB)
├─ Disk image: john-desktop-01_disk.img (MD5 hash: xxx)
├─ Event logs: Preserved (exported to USB)
├─ Chain of custody: Documented and verified
└─ Forensic examiner: [Name], [Certification], [Date]
```

---

## References

- Volatility Framework (memory analysis)
- Sleuth Kit / Autopsy (disk analysis)
- EnCase / FTK (commercial forensics)
- SANS Forensics Guide

---

*Document Maintenance:*
- Update tools as new versions released
- Test procedures quarterly
- Review real cases to improve methodology

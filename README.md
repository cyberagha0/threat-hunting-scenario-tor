
```
█████████        \  |  /               ████████
█████████         \ | /         _      █████████
   ███             \|/        .( ).    ███   ███
   ███          .---'---.    ( -+- )   ███   ███
   ███        .'         '.   '(_)'    █████████
   ███       /  .-------.  \           ████████
   ███      |  /  .---.  \  |          ███  ███
   ███      |  |  ( o )  |  |          ███   ███
   ███      |  \  '---'  /  |          ███   ███
   ███       \  '-------'  /           ███   ███
   ███        '.         .'            ███   ███
   ███          '-------'              ███   ███

        T H R E A T   H U N T   R E P O R T
     Unauthorized TOR Browser Installation & Use
```

![Platform](https://img.shields.io/badge/Platform-Microsoft_Defender_for_Endpoint-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/Query_Language-KQL-7D4698?style=for-the-badge)
![ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1090.003-C41E3A?style=for-the-badge)
![Result](https://img.shields.io/badge/Result-Confirmed_True_Positive-2EA043?style=for-the-badge)

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cyberagha0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "mleahy" (fictional suspected employee) downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-08-02T03:56:29.9529335Z`. These events began at `2026-08-02T03:37:29.4946339Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "corp-sda1-hs12"
| where InitiatingProcessAccountName == "mleahy"
| where FileName =~ "tor.exe" or FolderPath contains "Tor Browser"
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="941" height="758" alt="image" src="https://github.com/user-attachments/assets/46a365fd-d2b1-4fdc-8bab-03a4b29d6c53" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommanline that contained the string “ tor-browser-windows-x86_64-portable-15.0.19.exe ". Based on the logs returned,  at 11:37:29 PM on August 1, 2026, the user mleahy executed the Tor Browser installer on corp-sda1-hs12. The installer ran in silent mode using the /S argument, indicating an unattended installation. The executable was launched from the user's Downloads folder and its SHA-256 hash was recorded by Microsoft Defender for Endpoint. This activity shows that the Tor Browser was installed on the endpoint and may warrant further investigation due to its ability to anonymize network traffic. 


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "corp-sda1-hs12"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.19.exe"
| project Timestamp,DeviceName, ActionType, FileName, AccountName, FolderPath, SHA256, ProcessCommandLine
```
<img width="954" height="488" alt="image" src="https://github.com/user-attachments/assets/81f49606-0179-4257-b070-ecbcabce2a7b" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceprocessEvents table for any indication that user “mleahy” actually opened the tor browser. There was evidence that they did open it at 2026-08-02T03:37:53.9404246Z. There were several other instances of firefox.exe  (Tor) as well as tor.exe spawned afterwards.


**Query used to locate events:**

```kql
 DeviceProcessEvents
 | where DeviceName == "corp-sda1-hs12"
 | where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
 | order by Timestamp desc
 | project Timestamp,DeviceName, ProcessCommandLine, ActionType, FileName, AccountName, FolderPath, SHA256
```
<img width="916" height="706" alt="image" src="https://github.com/user-attachments/assets/8e54f2eb-6e28-4ddc-b82f-89069cbd6413" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 11:37:29 PM on August 1, 2026, the mleahy user account executed the Tor Browser executable (tor.exe) on the endpoint corp-sda1-hs12. The process was launched from C:\Users\mleahy\Desktop\Tor Browser\Browser\TorBrowser\Tor\, confirming it originated from the Tor Browser installation directory on the user's Desktop. The execution of tor.exe indicates that the Tor Browser was actively running and establishing connections to the Tor anonymity network. This activity may warrant further investigation if the use of anonymizing software violates the organization's security policy.


**Query used to locate events:**

```kql
 DeviceNetworkEvents
 | where DeviceName == "corp-sda1-hs12"
 | where InitiatingProcessAccountName == "mleahy"
 | where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
 | where RemotePort in ("9001","9002","9003","9030","9040","9050","9051","9052","9053","9150","9151", "80", "443")
 | project DeviceName, Timestamp, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath

```
<img width="935" height="602" alt="image" src="https://github.com/user-attachments/assets/a7fb5680-e788-4ead-b8ba-f73270c85d22" />

---

## Chronological Event Timeline 

# Threat Hunt: Unauthorized TOR Browser Usage

**Endpoint:** `corp-sda1-hs12` | **User:** `mleahy` | **Platform:** Microsoft Defender for Endpoint (KQL)
**Tables queried:** `DeviceFileEvents` · `DeviceProcessEvents` · `DeviceNetworkEvents`
**Incident window:** Aug 1, 2026 11:34 PM – Aug 2, 2026 8:35 PM (EDT — add 4 hours for UTC)

---

## Chronological Events

### Acquisition & Installation

| # | Time (EDT) | Table | Event |
|:--|:--|:--|:--|
| 1 | Aug 1 · 11:34:26 PM | File | Installer downloaded to `C:\Users\mleahy\Downloads\tor-browser-windows-x86_64-portable-15.0.19.exe`. `FileRenamed` marks the download completing (`.part` → final), fixing the true start of the incident. This is the **portable** build — no installer privileges required. |
| 2 | Aug 1 · 11:34:35 PM | Process / File | First execution, command line with **no arguments**. In the same second a `FileDeleted` removes the installer from Downloads — the extraction self-cleans, which is why the file is absent on disk today. |
| 3 | Aug 1 · 11:37:29 PM | Process | Re-executed with the **`/S` silent flag** — suppresses all prompts and the install-location dialog. Three minutes of idle time separate this from the first run. |
| 4 | Aug 1 · 11:37:40 PM | File | Payload written to `C:\Users\mleahy\Desktop\Tor Browser\`, including `Browser\TorBrowser\Tor\tor.exe` and bundled license docs (`tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt`). Desktop install path confirms **no admin rights were needed**. |
| 5 | Aug 1 · 11:37:45 PM | File | Desktop shortcut `Tor Browser.lnk` created. |

### Execution

| # | Time (EDT) | Table | Event |
|:--|:--|:--|:--|
| 6 | Aug 1 · 11:37:53 PM | Process | `firefox.exe` launched from `…\Desktop\Tor Browser\Browser\` (build ID `20260720080000`) — **8 seconds after install**. |
| 7 | Aug 1 · 11:37:54–57 PM | File | `storage.sqlite` and `storage-sync-v2.sqlite` written to `…\Data\Browser\profile.default\` — first-run profile creation, confirming a fresh install rather than a pre-staged copy. |
| 8 | Aug 1 · 11:37:56 PM | Process | `tor.exe` spawned by the browser with `-f …\Data\Tor\torrc`, `+__ControlPort 127.0.0.1:9151`, `+__SocksPort 127.0.0.1:9150`, and **`DisableNetwork 1`**. That flag is why no traffic leaves yet — it explains the ~25-second gap before event 10. |

### Network — TOR Connection Established

| # | Time (EDT) | Table | Event |
|:--|:--|:--|:--|
| 9 | Aug 1 · 11:37:57 PM | Network | `ConnectionSuccess` — `firefox.exe` → `127.0.0.1:9151`. Browser takes control of the TOR daemon and lifts `DisableNetwork`. |
| 10 | Aug 1 · 11:38:22–24 PM | Network | Three `ConnectionSuccess` events from `tor.exe` on **port 443** to `204.13.164.118`, `185.107.83.1`, `192.42.116.93`. Port 443 blends with normal HTTPS — **a port-based egress rule would not have caught these**. |
| 11 | Aug 1 · 11:38:25 PM | Network | `ConnectionSuccess` — `firefox.exe` → `127.0.0.1:9150` (SOCKS). From this point user web traffic exits via the TOR circuit, not the corporate proxy. |
| 12 | Aug 1 · 11:38:32 PM & 11:39:20 PM | Network | `tor.exe` → `70.134.248.71:9001`, both `ConnectionSuccess`. Port 9001 is the TOR **ORPort** — the single strongest and least ambiguous network indicator in this hunt. |

### Sustained Use

| # | Time (EDT) | Table | Event |
|:--|:--|:--|:--|
| 13 | Aug 1 · 11:38:35–11:40:41 PM | Process | ~10 `firefox.exe -contentproc -isForBrowser` children spawn, all sharing `-parentPid 14140`. Content processes map to tabs — real page loading over ~3 minutes, not an idle window. |
| 14 | Aug 1 · 11:45:05–06 PM | Process | Fresh `firefox.exe` (bare command line = new launch, not a tab) followed one second later by a new `tor.exe`. The browser was **closed and deliberately reopened** — repeat use. |
| 15 | Aug 1 · 11:56:29 PM | File | `tor-shopping-list.txt` created in `C:\Users\mleahy\Documents\`, alongside `tor-shopping-list.lnk` in `…\Windows\Recent\`. The Recent shortcut confirms the file was **opened by the user**, not merely written. |
| 16 | Aug 1 · 11:56:42 PM | File | Same filename with an **identical SHA-256** created on the Desktop — proving a copy, not a second document. |

### Follow-On Activity (Next Day)

| # | Time (EDT) | Table | Event |
|:--|:--|:--|:--|
| 17 | Aug 2 · 8:35:25 PM | File | `Tor Browser.lnk` created in `…\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\` — moving the shortcut into the Start Menu indicates intent to keep using it. |
| 18 | Aug 2 · 8:35:28 PM | File | `FileDeleted` on `…\TorBrowser\Tor\tor.exe`, **three seconds** after the shortcut was created. Install-for-convenience then immediately remove the core binary is contradictory and warrants a direct interview. |

---

## Summary

User `mleahy` downloaded, silently installed, and actively used the TOR Browser on `corp-sda1-hs12` on the night of August 1, 2026.

The portable build and `/S` flag meant **no admin rights and no prompts**. Within a minute of launch, the TOR client connected out to external infrastructure on ports **443 and 9001** and the browser bound to the local SOCKS proxy — so the connection **succeeded**, and that session's traffic left the network anonymized, outside proxy, filtering, and DLP visibility.

Usage was sustained rather than exploratory: about ten tabs over three minutes, a deliberate second launch at 11:45 PM, and a `tor-shopping-list.txt` file created in Documents, opened, and copied to the Desktop. The next evening a Start Menu shortcut was added and `tor.exe` was deleted.

All three IoC checks returned positive and corroborate one another across file, process, and network telemetry.

---

## Indicators of Compromise

| Type | Value | Context |
|:--|:--|:--|
| SHA-256 | `0d4cc3a7b734a10c500217fb0df89452ee39185709193966831677bbd43c98f8` | TOR Browser installer |
| SHA-256 | `ec7708e0b43e0e00b1533d11ed3ca244e6f11cb2a7b62d319ad73a7b13123033` | `tor.exe` |
| SHA-256 | `d3bd730d253ca068f78561394c0097a8fd40210eb60d864574c1821b2c1c9de7` | `firefox.exe` (TOR build) |
| SHA-256 | `e9d82e62acc7c4f2f87151556e6c6bd9961bf89a603f80b3368e77781b7eab67` | `tor-shopping-list.txt` (both copies) |
| IP:Port | `204.13.164.118:443`, `185.107.83.1:443`, `192.42.116.93:443` | Outbound from `tor.exe` |
| IP:Port | `70.134.248.71:9001` | TOR relay ORPort |
| Path | `C:\Users\mleahy\Desktop\Tor Browser\` | Install directory |

---

## Response Taken

TOR usage was confirmed on endpoint `corp-sda1-hs12`. The device was **isolated** and the user's **direct manager was notified**.

### Recommended Follow-Up

- [ ] Preserve both copies of `tor-shopping-list.txt` and the Desktop `Tor Browser` directory before reimaging; review contents.
- [ ] Block the installer and `tor.exe` hashes as Defender custom indicators.
- [ ] Validate the four external IPs against the public TOR relay consensus, then add TOR ports to egress deny rules.
- [ ] Interview the user about the Aug 2 deletion of `tor.exe` and confirm no other copy remains on the host.
- [ ] Run the same IoCs tenant-wide — management reported TOR entry-node traffic, so this host may not be the only one.
- [ ] Review application control (WDAC/AppLocker): a standard user installed and ran unapproved software from the Desktop.

---

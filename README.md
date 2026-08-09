
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

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

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---

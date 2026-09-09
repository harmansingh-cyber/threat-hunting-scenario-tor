<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/harmansingh-cyber/threat-hunting-scenario-tor/tree/main) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Queried the DeviceFileEvents table for files containing the strings "tor" or "firefox". The investigation identified activity associated with the user employee that appears to indicate the download of a Tor Browser installer. Following the download, multiple Tor-related files were copied to the user's Desktop, along with the creation of a file named tor.txt. The activity may indicate an attempt to install, execute, or otherwise interact with Tor-related software. The identified activity began at `2026-09-02T02:43:07.4430382Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-har"
| where FileName startswith "tor"
| where InitiatingProcessAccountName == "employee"
| where Timestamp >= datetime(2026-09-02T02:43:07.4430382Z)
| where FileName has_any ("tor", "firefox")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, Account = InitiatingProcessAccountName,
         InitiatingProcessFileName, InitiatingProcessCommandLine,
         SHA1, SHA256
| order by Timestamp desc
```
<img width="1704" height="409" alt="Screenshot 2026-09-09 at 1 53 55 AM" src="https://github.com/user-attachments/assets/82ba0e3b-9fe4-41eb-bd53-787149e522e3" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any process command line containing `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.21.exe`. According to the logs, at **2026-09-02T02:55:19.107892Z**, activity was observed on the **`threat-hunt-har`** device under the account **`employee`**, showing the Tor Browser portable executable located in the user's Downloads directory. The executable was invoked with the **`/S`** command-line parameter, which indicates silent installation or execution. This activity is consistent with the user downloading and subsequently invoking the Tor Browser portable executable.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-har"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.21.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1712" height="170" alt="Screenshot 2026-09-09 at 1 56 19 AM" src="https://github.com/user-attachments/assets/e42399e0-6f99-4394-93a5-cae05b8521fc" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for evidence that the user **`employee`** opened the Tor Browser. The logs confirmed that the Tor Browser was first opened at **2026-09-02T02:55:57.0803135Z**, followed by several additional instances of **`firefox.exe`** associated with Tor Browser activity. Shortly afterward, **`tor.exe`** processes were also observed spawning, providing further evidence that the Tor Browser was successfully launched and operational on the device.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-har"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1689" height="651" alt="Screenshot 2026-09-09 at 1 58 22 AM" src="https://github.com/user-attachments/assets/a9fda3e8-f5c3-4365-bb4d-7e2afa2d12e9" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for indications that the Tor Browser was used to establish network connections over known Tor ports. At **2026-09-02T03:05:43.9901027Z**, the **`threat-hunt-har`** device, under the account **`employee`**, was observed successfully establishing a network connection through the Tor Browser's **`tor.exe`** process running from the user's Desktop directory. The connection was made to the remote IP address **144.76.140.110** over **port 9030**, a port historically associated with Tor relay and directory traffic. Additional network connections were also observed over **ports 443 and 80**. Overall, the events provide evidence that the employee's system successfully established network connectivity through the Tor Browser and communicated with the Tor network.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-har"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030","9040","9050","9051","9150","80","443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1745" height="472" alt="Screenshot 2026-09-09 at 1 59 47 AM" src="https://github.com/user-attachments/assets/e324bddd-bcd5-48ef-bd52-d37d93bfb1da" />

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

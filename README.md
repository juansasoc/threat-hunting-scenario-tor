# threat-hunting-scenario-tor
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/juansasoc/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

![unauthorized use of darknet at work](https://github.com/user-attachments/assets/bf0e7a72-4985-461f-a00c-13bb2cd7b9fb)


### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “torboi” downloaded a tor installer, or did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 2025-04-11T22:31:26.3698616Z


**Query used to locate events:**

```kql
DeviceFileEvents 
| where DeviceName == "rivj-tor-vm" 
| where InitiatingProcessAccountName  == "torboi" 
| where FileName contains "tor" 
| where Timestamp >= datetime(2025-04-11T22:31:26.3698616Z) 
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName 
```
![image](https://github.com/user-attachments/assets/55ebd6b6-05b7-44d8-b0e7-6c155a28f97b)



---

### 2. Searched the `DeviceProcessEvents` Table 

Searched the DeviceProcessEvents table for any indication that user “torboi” actually opened the tor browser. There was evidence that they did open it at:  Apr 11, 2025 5:32:07 PM . There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterward 


**Query used to locate event:**

```kql
DeviceProcessEvents 
| where DeviceName == "rivj-tor-vm" 
| where FileName has_any ("tore.exe", "firefox.exe", "tor-browser.exe") 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine 
| order by Timestamp desc 

```
![image](https://github.com/user-attachments/assets/abcc4680-fb4b-4544-9266-754d04e0de55)
>

---

### 3.  Searched the `DeviceNetworkEvents` Table for TOR Network Connections

 Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. On April 11, 2025, at 5:32 PM, a virtual machine named "rivj-tor-vm" had a user account called "torboi" that successfully made a network connection. The connection was made 
 to the IP address 192.42.132.106, specifically to the website: https://www{.}c5yraaw54zp6bfs7n[.]com . The program that made the connection was Tor (a privacy-focused browser), and it was run from this location: 
 C:\Users\torboi\Desktop\Tor Browser\Browser\TorBrowser\tor\tor.exe 

**Query used to locate events:**

```kql
DeviceNetworkEvents 
| where DeviceName == "rivj-tor-vm" 
| where InitiatingProcessAccountName != "system" 
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150") 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath 
| order by Timestamp desc 
```
![image](https://github.com/user-attachments/assets/635a485e-dc76-4732-ab8b-0a559d98fd6a)


---


<>

---

### 4.

## Chronological Event Timeline 

🟢 1. Installation Activity
Tor Browser Installation
🕒 5:31:28 PM

User "torboi" on virtual machine "rivj-tor-vm" launched the Tor Browser installer:
tor-browser-windows-x86_64-portable-14.0.9.exe

Location: C:\Users\torboi\Downloads

🌐 2. Network Activity
Tor Network Connections
🕒 5:32:29 PM

The Tor process (tor.exe) successfully connected to IP address 192.42.132.106.

A connection was made to the hidden website:
https://www[.]c5yraaw54zp6bfs7n[.]com

🕒 5:32:29 PM

Another connection to 192.42.132.106 was logged by the same tor.exe process.

🕒 5:32:39 PM

The Tor Browser's Firefox component (firefox.exe) connected to 127.0.0.1 (localhost), showing it was routing traffic through the local Tor service as expected.

⚙️ 3. Process Creation
Tor and Firefox Processes
🕒 5:33:25 PM – 5:34:28 PM

Multiple Firefox browser processes were launched by the Tor Browser.

This likely represents the browser opening tabs or loading content.

Location:
C:\Users\torboi\Desktop\Tor Browser\Browser\firefox.exe

📝 4. File Activity
Browser and User Files
🕒 5:36:36 PM

File formhistory.sqlite was created in the Tor Browser folder.
Stores form data (e.g., autofill history).

🕒 5:38:20 PM

File webappsstore.sqlite was created.
Stores local web app data (like cookies or cached content).

User File: tor-shopping-list
🕒 5:38:37 PM

File tor-shopping-list.txt was renamed.

A shortcut (.lnk) version was also created in the "Recent Files" folder, showing it was accessed.

🕒 5:39:02 PM

The tor-shopping-list.txt file was modified again on the Desktop.



## 📅 Full Timeline Overview (Summarized Chronologically)

| Time           | Event Type         | Summary                                                                 |
|----------------|--------------------|-------------------------------------------------------------------------|
| **5:31:28 PM** | Installation       | Tor Browser installer launched by user "torboi".                        |
| **5:32:29 PM** | Network            | Tor connects to hidden service IP & website.                            |
| **5:32:39 PM** | Network            | Firefox connects locally to the Tor service (127.0.0.1).                |
| **5:33–5:34 PM**| Process Creation  | Multiple Firefox processes are launched by the browser.                 |
| **5:36:36 PM** | File Creation      | Form history file created in Tor Browser folder.                        |
| **5:38:20 PM** | File Creation      | Web storage file created (likely from browsing activity).               |
| **5:38:37 PM** | File Rename/Shortcut| `tor-shopping-list.txt` renamed and shortcut created.                   |
| **5:39:02 PM** | File Modified      | `tor-shopping-list.txt` modified on Desktop.                            |


 

 

---

## Summary

The user "torboi" on the "rivj-tor-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `rivj-tor-vm` by the user `torboi`. The device was isolated, and the user's direct manager was notified.

---

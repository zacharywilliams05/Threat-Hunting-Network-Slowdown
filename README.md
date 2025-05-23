# 1. Preparation

**Goal:** Set up the hunt by defining what you're looking for.

The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the `10.0.0.0/16` network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

**Activity:** Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).

All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

# 2. Data Collection

**Goal:** Gather relevant data from logs, network traffic, and endpoints.

Inspect logs for excessive successful/failed connections from any devices. If discovered, pivot and inspect those devices for any suspicious file or process events. We will be using the following tables:
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceProcessEvents`

___

I created this KQL query to find devices with a high number of failed connections:

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, LocalIP, ActionType
| order by ConnectionCount
```

![Screenshot 1 Device with most Failed Connections](https://github.com/user-attachments/assets/3aafdb24-3f0f-4887-9457-f602422095ec)

The query produces a list of devices with a high number of failed connections. "vm-lab-andre" has the highest number of failed connections. This is a good place to start looking.

# 3. Data Analysis

**Goal:** Analyze data to test hypothesis.

Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques.

```kql
DeviceNetworkEvents
| where DeviceName == "vm-lab-andre" and ActionType == "ConnectionFailed"
| order by Timestamp asc
```

![Screenshot 2 List of RemotePorts being scanned](https://github.com/user-attachments/assets/c513bfd2-b844-4841-947a-dccf8df65a40)

The KQL query results clearly show a pattern of port scanning. Approximately every 3 seconds, "vm-lab-andre" at local IP address 10.0.234 checks a well-known port number, increments to the next well-known port, and tries again. This seems to be happening against both internal and external IP addresses.

# 4. Investigation

**Goal:** Investigate any suspicious findings.

**Activity:** Dig deeper into detected threats, determine their scope, and escalate if necessary. See if anything you find matches TTPs within the MITRE ATT&CK Framework.

Search the `DeviceFileEvents` and `DeviceProcessEvents` tables around the same time based on your findings in the `DeviceNetworkEvents` tables to see if you can find more evidence for the cause of network slowdowns. You can use ChatGPT to figure this out by pasting/uploading the logs: Scenario 2 - TTPs.

___

Moving to the `DeviceProcessEvents` table, we checked if any suspicious processes were initiated around the time the port scan started at `2025-05-18T20:37:53.3327339Z`.

```kql
let VMname = "vm-lab-andre";
let scannedStartTime = datetime(2025-05-18T20:37:53.3327339Z);
DeviceProcessEvents
| where Timestamp between ((scannedStartTime - 10m) .. (scannedStartTime + 10m))
| where DeviceName == VMname
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

![Screenshot 3 DeviceProcessEvents powershell portscan script](https://github.com/user-attachments/assets/9ec1c0e2-537c-44bf-8a73-26e01fc5d846)

We see that a PowerShell script titled portscan.ps1 was executed approximately 30 seconds before the port scan started at 2025-05-18T20:37:24.920634Z (Please keep in mind the time in the KQL query is GMT while the time in the results are local Japan time).

We now know where the script is located, so we can look at it in C:\Programdata\portscan.ps1.

![Screenshot 4 portscan script](https://github.com/user-attachments/assets/52d196f6-bbb4-4c4b-89ed-9ec1b6db7ee8)

![Screenshot 5 portscan logfile](https://github.com/user-attachments/assets/81877377-49f7-45e9-8a81-d741c3fce763)

These scripts are responsible for the port scan.

For the sake of this exercise, we can observe which AccountName launched this command:

```kql
let VMname = "vm-lab-andre";
let scannedStartTime = datetime(2025-05-18T20:37:53.3327339Z);
DeviceProcessEvents
| where Timestamp between ((scannedStartTime - 10m) .. (scannedStartTime + 10m))
| where DeviceName == VMname
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, AccountName, InitiatingProcessCommandLine
```

![Screenshot 6 AccountName](https://github.com/user-attachments/assets/27558a24-82d2-4399-af71-0ab939a18e64)

It appears it was launched by the system. In a real-life scenario, we may be able to attribute the script to a user or service account and investigate further. In this case, the other security admins and the team running the device VM-Lab-Andre do not know why this script is here and why it is being executed.

# 5. Response

**Goal:** Mitigate any confirmed threats.

**Activity:** Work with security teams to contain, remove, and recover from the threat.

Can anything be done?

___
![Screenshot 7 quarantineing the device](https://github.com/user-attachments/assets/ab7bd096-2480-44dd-8b2e-25c23e3d6636)

As such, we ran a malware scan which did not show any trace of malware. We quarantined the device and rebuilt it. We would then want to investigate other devices in the logs that may be showing similar activity.

___

# 6. Documentation

**Goal:** Record your findings and learn from them.

**Activity:** Document what you found and use it to improve future hunts and defenses.

Document what you did

___

These notes and screenshots were added to the incident ticket.

___

# 7. Improvement

**Goal:** Improve your security posture or refine your methods for the next hunt.

**Activity:** Adjust strategies and tools based on what worked or didn’t.

Anything we could have done to prevent the thing we hunted for? Any way we could have improved our hunting process?

___

___

## MITRE ATT&CK Framework TTPs:

1. **Tactic: Initial Access**
   - **Technique: Valid Accounts (T1078)**: If the port scanning was initiated by a legitimate account, it could indicate that an attacker is using valid credentials to gain access.

2. **Tactic: Discovery**
   - **Technique: Network Service Scanning (T1046)**: The observed behavior of scanning well-known ports on both internal and external IP addresses corresponds to this technique, as it involves identifying services running on networked devices.

3. **Tactic: Execution**
   - **Technique: PowerShell (T1059.001)**: The execution of a PowerShell script (`portscan.ps1`) to perform the port scan directly corresponds to this technique, as it involves using PowerShell for command execution.

4. **Tactic: Persistence**
   - **Technique: Scheduled Task/Job (T1053)**: If the script is set to run at specific intervals or conditions, it could indicate a persistence mechanism.

5. **Tactic: Collection**
   - **Technique: Data from Information Repositories (T1213)**: If the scanning is part of a broader effort to collect information about the network, this technique may apply.



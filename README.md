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

From this, we can see the list of devices with a high number of failed connections, with "vm-lab-andre" being the highest. Let's take a closer look at this device.

# 3. Data Analysis

**Goal:** Analyze data to test hypothesis.

Look for anomalies, patterns, or indicators of compromise (IOCs) using various tools and techniques.

```kql
DeviceNetworkEvents
| where DeviceName == "vm-lab-andre" and ActionType == "ConnectionFailed"
| order by Timestamp asc
```

![Screenshot 2 List of RemotePorts being scanned](https://github.com/user-attachments/assets/c513bfd2-b844-4841-947a-dccf8df65a40)

These results clearly show a pattern of the device port scanning. Approximately every 3 seconds, vm-lab-andre at local IP address 10.0.234 checks a well-known port number, increments to the next well-known port, and tries again. This seems to be happening against both internal and external IP addresses.

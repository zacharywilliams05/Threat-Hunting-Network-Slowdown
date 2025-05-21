# 1. Preparation

**Goal:** Set up the hunt by defining what you're looking for.

The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the `10.0.0.0/16` network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

**Activity:** Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).

All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

# 2. Data Collection

**Goal:** Gather relevant data from logs, network traffic, and endpoints.

Consider inspecting the logs for excessive successful/failed connections from any devices. If discovered, pivot and inspect those devices for any suspicious file or process events.

**Activity:** Ensure data is available from all key sources for analysis.

Ensure the relevant tables contain recent logs:
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

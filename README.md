

## Threat Hunt Report: Sudden Network Slowdown

**Scenario:**

We noticed a sudden slowdown on some of our older devices within the `10.0.0.0/16` network. We quickly ruled out external DDoS attacks, which immediately shifted our focus to internal network activity. Our environment is pretty permissive, allowing unrestricted PowerShell use and local traffic by default, so we knew we had a few avenues to explore.

-----

### 1\. Getting Started: Setting the Stage

**Our Goal:** Figure out what was going on.

**Hypothesis:**

Given how open our network is and the observed slowdown, our initial hunch was that some internal activity was causing the trouble. This could be anything from someone downloading something massive to a device doing some unexpected port scanning. We also considered the possibility of an attacker moving laterally through our network.

-----

### 2\. Gathering the Clues: What the Logs Told Us

**Our Goal:** Collect the necessary logs to either prove or disprove our hypothesis.

**Where We Looked (via Microsoft Defender for Endpoint):**

We pulled data from:

  - `DeviceNetworkEvents`
  - `DeviceFileEvents`
  - `DeviceProcessEvents`

**Quick Check:** We made sure we had all the latest and greatest logs from these tables – no missing pieces here\!

-----

### 3\. Digging In: Analyzing the Data

**Our Goal:** Spot anything out of the ordinary or any indicators of compromise (IOCs).

**How We Did It:**

We started by looking at **failed connections**. If we found anything suspicious there, we planned to pivot to file and process logs to get a clearer picture.

### What We Found:

1.  We saw a huge number of `ConnectionFailed` events coming from a device named `ace-mde-test` within our `10.0.0.0/16` network. This immediately caught our eye.

    ```kusto
    DeviceNetworkEvents
    | summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
    | where ActionType == "ConnectionFailed"
    | order by ConnectionCount
    ```

2.  When we drilled down, we noticed a sequence of failed connections originating from `10.1.0.50`. This kind of activity is often a tell-tale sign of **port scanning**. Someone (or something) was trying to figure out what services were running on other devices.

    ```kusto
    let IPInQuestion = "10.1.0.50";
    DeviceNetworkEvents
    | where ActionType == "ConnectionFailed"
    | where LocalIP == IPInQuestion
    | order by Timestamp desc
    ```

-----

### 4\. The Deep Dive: Investigating and Mapping to MITRE ATT\&CK

**Our Goal:** Confirm our suspicions and connect the dots to known attacker tactics and techniques.

**Our Next Step:** Since port scanning was evident, we pivoted to `DeviceProcessEvents` to see what processes were running on `ace-mde-test` at the time of the scanning.

### What Else We Uncovered:

  - We discovered that a PowerShell script called `portscan.ps1` was executed on `ace-mde-test` at `2025-06-22T16:26:36Z`. That's a pretty big red flag right there\!

    ```kusto
    let VMName = "ace-mde-test";
    let specificTime = datetime(2025-06-22T16:26:36.7739838Z);
    DeviceProcessEvents
    | where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
    | where DeviceName == VMName
    | order by Timestamp desc
    | project Timestamp, FileName, InitiatingProcessCommandLine
    ```

  - The script's location was `C:\ProgramData\portscan.ps1`, and it was executed using `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\portscan.ps1`. The `-ExecutionPolicy Bypass` part is particularly concerning as it allows any script to run, regardless of signing.

  - Even more alarmingly, the script was launched by the **SYSTEM account**. This is highly unusual and suggests a significant privilege escalation or compromise, as the SYSTEM account has extensive permissions.

### Connecting the Dots: MITRE ATT\&CK TTPs

Here's how this activity maps to the MITRE ATT\&CK framework, helping us understand the attacker's potential goals:

| Tactic | Technique | Description |
|---|---|---|
| [TA0007 – Reconnaissance](https://attack.mitre.org/tactics/TA0007) | [T1046 – Network Service Scanning](https://attack.mitre.org/techniques/T1046) | The port scan was clearly an attempt to identify active services and potential targets. |
| [TA0002 – Execution](https://attack.mitre.org/tactics/TA0002) | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001) | The attacker leveraged PowerShell to execute their malicious script. |
| [TA0006 – Credential Access](https://attack.mitre.org/tactics/TA0006) | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078) | The use of the SYSTEM account indicates the compromise or misuse of a highly privileged valid account. |

-----

### 5\. Taking Action: Containing and Remediating

**Our Goal:** Shut down the threat and clean up the affected system.

### What We Did:

  - We immediately **isolated `ace-mde-test`** from the rest of the network to prevent any further spread or activity.
  - We then kicked off a **full malware scan** on the isolated device.

### The Outcome:

  - Interestingly, the malware scan came back **clean**. This suggests that while the script was unauthorized and malicious, it might not have been traditional malware, or it was part of a larger, more sophisticated attack.
  - However, given that unauthorized scripts were executed at the **SYSTEM level**, which is a critical security breach, we've decided to keep the device isolated and plan for a **full re-imaging**. This ensures we completely remove any lingering threats or backdoors.

-----

### 6\. Documenting Our Work: Learning and Improving

**Our Goal:** Make sure everything is documented so we can learn from this incident and improve our defenses.

  - This report covers all the essential details: our initial thoughts (hypothesis), where we got our data, the exact queries we used (KQL), how we mapped the attacker's actions to MITRE ATT\&CK, and what we did to respond.
  - All the KQL queries are included, so anyone can easily reproduce our findings and validate our steps.

-----

### 7\. Moving Forward: Preventing Future Attacks

### Our Preventative Measures:

We've identified several key areas where we can strengthen our defenses to prevent similar incidents:

  - **Network Segmentation:** We need to implement stricter **VLANs or internal firewalls**. This will help limit lateral movement, making it much harder for an attacker to jump from one compromised device to another.
  - **PowerShell Restrictions:** PowerShell is powerful, but it needs tighter controls. We'll:
      - **Enable comprehensive PowerShell logging** to capture every command.
      - **Enforce constrained language mode** to restrict what PowerShell can do.
      - **Block unapproved scripts** from running.
  - **Least Privilege:** We need to be more vigilant about who has what access. This means:
      - Regularly **auditing SYSTEM and other privileged account behavior** for anything out of the ordinary.
      - **Restricting unnecessary privileges** across the board.
  - **Alert Tuning:** Our alerts need to be smarter. We'll fine-tune them to:
      - **Trigger on unusual PowerShell usage**.
      - **Flag rapid failed connection attempts** immediately, as these are often signs of scanning or brute-force attacks.

-----

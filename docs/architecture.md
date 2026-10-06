# LAB-DET-001 Architecture

## Detection path

```mermaid
flowchart TB
    subgraph Analyst["Analyst layer"]
        SA[SOC Analyst Workstation]
    end

    subgraph Endpoint["Endpoint layer"]
        EP[Windows Endpoint]
        SY[Sysmon Event ID 1]
        PS[PowerShell Operational Event ID 4104]
        AG[Wazuh Agent]
        EP --> SY
        EP --> PS
        SY --> AG
    end

    subgraph SOC["SOC layer"]
        WM[Wazuh Manager]
        NR[Native rules 92027 / 92057]
        CR[Custom rule 100100]
        UI[Wazuh Threat Hunting / Document Details]
        WM --> NR
        WM --> CR
        NR --> UI
        CR --> UI
    end

    AG -->|Windows event-channel telemetry| WM
    SA -->|HTTPS investigation| UI

    subgraph Supporting["Supporting infrastructure"]
        FW[pfSense segmentation]
        DC[Domain Controller / time source]
    end

    DC -. time sync .-> EP
    FW --- SA
    FW --- EP
    FW --- WM
```

## Data flow

```text
controlled PowerShell activity
-> Windows process creation
-> Sysmon Event ID 1
-> Wazuh Agent
-> Wazuh Manager
-> native/custom rule evaluation
-> alert
-> analyst validation
```

PowerShell Event ID 4104 was independently confirmed locally during the controlled tests and used as supporting telemetry evidence.

## Scope decision

Security Onion was intentionally not introduced into LAB-DET-001 because the detection question was endpoint/process based. The permanent SOC lab already provided the required host telemetry through Wazuh.

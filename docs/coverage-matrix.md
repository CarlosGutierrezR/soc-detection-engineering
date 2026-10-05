# Coverage Matrix — PowerShell Encoded Execution



## Objetivo



Evaluar la cobertura nativa de Wazuh para ejecuciones de PowerShell con argumentos codificados y documentar posibles gaps de detección antes de diseñar una regla personalizada.



## Telemetría disponible



- Sysmon Event ID 1 — Process Creation

- Microsoft-Windows-PowerShell/Operational Event ID 4104 — Script Block Logging

- Wazuh Agent 4.14.7

- Wazuh Manager 4.14.7



## Resultados verificados



| Test | Parent Process | Argumento | Sysmon EID 1 | PowerShell 4104 | Wazuh Rule | Level | Resultado |

|---|---|---|---|---|---|---:|---|

| TC-01 | powershell.exe | `-EncodedCommand` | Sí | Sí | 92057 | 12 | Detectado como encoded PowerShell |

| TC-02 | powershell.exe | `-enc` | Sí | Sí | 92027 | 4 | Visible, pero no clasificado como encoded PowerShell |



## Evidencia TC-01



Comando controlado:



```powershell

powershell.exe -NoProfile -EncodedCommand <BASE64>



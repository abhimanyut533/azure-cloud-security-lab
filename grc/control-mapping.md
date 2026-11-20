# Control mapping — CIS Microsoft Azure Foundations Benchmark & ISO/IEC 27001:2022

**Scenario (fictional):** *"PetitCommerce SAS"*, a 50-person Paris e-commerce company that just moved a reporting
app to Azure. This lab reproduces its first, rushed deployment (insecure) and the corrected one (secure).

> **To do (Day 11):** download the current CIS Microsoft Azure Foundations Benchmark (free PDF from CIS after
> registration) and write the **exact recommendation numbers** in the CIS column. Section names are given here
> because numbers change between benchmark versions.

## 1. Misconfiguration → controls

| Finding (posture_check rule) | CIS Azure Benchmark section | ISO 27001:2022 Annex A | Insecure | Secure |
|---|---|---|---|---|
| AZ-STG-01 / AZ-STG-04 Public blob access | Storage Accounts — anonymous blob access disabled | A.5.15 Access control · A.8.3 Information access restriction · A.8.12 Data leakage prevention | ❌ | ✅ |
| AZ-NET-01 SSH open to Internet | Networking — SSH/RDP access from the Internet restricted | A.8.20 Networks security · A.8.22 Segregation of networks | ❌ | ✅ |
| AZ-IAM-01 Contributor on subscription | Identity / IAM — least privilege for identities | A.8.2 Privileged access rights · A.5.15 · A.5.18 Access rights | ❌ | ✅ |
| AZ-VM-01 Password SSH | Virtual Machines — key-based authentication | A.8.5 Secure authentication | ✅ | ✅ |
| AZ-LOG-01 Activity Log exported | Logging and Monitoring — Activity Log exported | A.8.15 Logging · A.8.16 Monitoring activities | ✅ | ✅ |
| [CIS ID] | | | | |

## 2. Detection → controls (evidence that monitoring works)

| Detection | ISO 27001:2022 | What an auditor could see |
|---|---|---|
| C01 SSH brute force | A.8.5, A.8.16, A.8.20 | Sentinel rule, incidents, real scanner IP counts |
| C02 Role assigned | A.8.2, A.5.15, A.5.18 | Alert on every new role, compared to approved access requests |
| C03 NSG rule changed | A.8.20, A.8.9, A.8.32 Change management | Alert vs. change tickets |
| C04 Anonymous blob read | A.5.15, A.8.3, A.8.12 | StorageBlobLogs + alert |
| C05 Diagnostic setting deleted | A.8.15, A.8.16, A.5.28 Collection of evidence | Alert; logs already stored centrally |

Process controls supported by the whole lab: **A.5.23** Information security for use of cloud services,
**A.5.24/A.5.26** incident management and response (incident report), **A.5.27** learning from incidents
(lessons learned), **A.8.9** configuration management (everything is code, reviewed in Git).

## 3. Gaps that remain in secure mode

| Gap | Control | Recommendation | Priority |
|---|---|---|---|
| VM still has a public IP | A.8.20 | Azure Bastion or Just-In-Time access, no public IP | Medium |
| Storage uses shared keys | A.8.5 | Disable shared key auth, use Entra ID + RBAC | Medium |
| No Entra ID sign-in logs | A.8.16 | Entra ID P1/P2 + sign-in log export | Medium |
| No automated response | A.5.26 | Sentinel automation rule / playbook | Low |
| _add your own_ | | | |

_Learning exercise on a fictional company — not a certification document._

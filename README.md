# 🛡️ Audit-SYSVOLPermissions

**🔍 PowerShell script to detect unauthorized NTFS permissions on SYSVOL.**  
**⭐ Complements [Harden-Sysvol](https://github.com/username/Harden-Sysvol) for a complete Active Directory GPO security audit.***

---

📂 **Purpose**  
This project aims to **join and strengthen** the security posture enforced by [Harden-Sysvol](https://github.com/username/Harden-Sysvol) by focusing on **access control (ACL) auditing** inside the SYSVOL share.

---
✨ **Features**
- Detects **non-inherited** NTFS permissions on SYSVOL files and folders
- Identifies permissions granted to **untrusted or unexpected accounts**
- Provides **clear alerts** with identity and file path
- Designed for **incident response**, **AD hardening**, and **compliance audits**
- Fully compatible with Harden-Sysvol workflows
---

📌 **Sample Alert**
⚠️ ALERT: DOMAIN\UserX has 'Modify' on \domain.local\SYSVOL\domain.local\Policies{GUID}\scripts\malicious.ps1

## 🚀 How to Use
### 🛠️ Prerequisites

- 🖥️ **Domain-joined Windows machine
- 👤 A **standard domain user account** (no admin rights required)

> ✅ Download the Script PS1 in the section and run it from ISE or Powershell

🧰 **Use Cases**
- GPO security assessment
- Detecting lateral movement risks
- Red team/blue team auditing
- Forensic investigation

⭐ If you find this tool useful, don't forget to **star** the repository and share it with your team!

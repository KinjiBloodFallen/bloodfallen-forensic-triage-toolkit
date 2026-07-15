<img width="1917" height="1018" alt="image" src="https://github.com/user-attachments/assets/8250a1a5-9f5c-454f-b63a-b067948b7a1c" />
# BloodFallen Forensic Triage Toolkit

**Version 1.0.0** — first public release.

A read-only, evidence-collection PowerShell tool for basic malware/persistence inspection on Windows. Built for local and community use — it does **not** delete files, kill processes, disable services, remove scheduled tasks, modify the registry, read cookies/passwords, or send your files anywhere.

> **Disclaimer:** This tool uses heuristic pattern-matching (suspicious paths, unsigned binaries, common LOLBin abuse patterns, etc.). A `[HIGH]` or `[MEDIUM]` result is a signal to investigate further — **not proof of infection.** Likewise, a clean report is not a guarantee your system is malware-free. Use this alongside, not instead of, a real antivirus/EDR product.

---

## Features

- System information & environment snapshot
- Startup commands, Run/RunOnce registry entries, Startup folder entries
- Scheduled tasks and Windows services review
- WMI persistence check
- Suspicious running process check
- Established network connections
- Recently modified suspicious files (configurable lookback window)
- Microsoft Defender status, exclusions, and manual scan triggers
- Hosts file / proxy / DNS sanity check
- Manual file hash + Authenticode signature check, with **optional** VirusTotal hash lookup (SHA256 only — the file itself is never uploaded)
- Browser extension inventory (no cookies, passwords, tokens, or history are read)
- Full evidence report export + one-click ZIP export of all logs

Every check writes a timestamped log to a local `BloodFallen_Logs` folder next to the script.

---

## Requirements

- Windows 10/11
- PowerShell 5.1 (built into Windows) or PowerShell 7+
- Administrator privileges recommended for full results (some checks, like services and certain scheduled tasks, are limited without it — the script will tell you which)

---

## Quick Start

1. Download `BloodFallen.ps1` (or clone the repo).
2. **Unblock the file** (see [Troubleshooting](#troubleshooting) below — Windows blocks scripts downloaded from the internet by default).
3. Right-click the script → **Run with PowerShell**, or from a PowerShell window:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\BloodFallen.ps1
   ```
4. Use the on-screen menu. Press `A` at any time to relaunch elevated as Administrator.

---

## Troubleshooting

These are near-guaranteed to come up for first-time users — please read before opening an issue.

### "This system is blocking the file" / script won't run at all
Windows tags files downloaded from the internet with a "Mark of the Web," which blocks scripts by default. Fix it one of two ways:

**Option A — Right-click:**
1. Right-click `BloodFallen.ps1` → **Properties**
2. At the bottom of the **General** tab, check **Unblock** → **OK**

**Option B — PowerShell:**
```powershell
Unblock-File -Path .\BloodFallen.ps1
```

### "running scripts is disabled on this system"
This is Windows' default PowerShell execution policy, not a bug in the script. Run the script with a one-time bypass instead of changing your system-wide policy:
```powershell
powershell -ExecutionPolicy Bypass -File .\BloodFallen.ps1
```
This only affects that one launch — it does **not** permanently change your execution policy.

### My antivirus flagged or quarantined the script itself
This is a known false-positive risk for *any* security-inspection script, ironic as that sounds. The script contains strings like `EncodedCommand`, `bypass`, `mshta`, `rundll32`, `invoke-expression`, etc. — because it's searching *for* those patterns in other files/commands, not because it uses them maliciously. Heuristic AV engines sometimes flag files containing these strings regardless of context.

What to do:
- Read the source yourself — it's a single plain-text `.ps1` file, nothing is obfuscated or hidden.
- Submit it to your AV vendor as a false positive if you're comfortable.
- If you're cautious (which is reasonable!), run it in a sandbox/VM first.

### "Access denied" on some checks (services, certain scheduled tasks, network connections)
You're not running as Administrator. Relaunch elevated using option **A** on the main menu, or right-click the script → **Run as administrator**. The script will always tell you when it's running in limited mode.

### VirusTotal lookups say "Skipped - no VirusTotal API key configured"
This is expected out of the box — VirusTotal checks are opt-in only. See the [FAQ](#faq) below for how to add a key.

---

## FAQ

**Q: Does this replace my antivirus?**
No. This is a supplementary inspection/evidence-collection tool, not real-time protection. Keep Defender or your AV product running.

**Q: Does it send any of my files anywhere?**
No. The only thing that ever leaves your machine is a SHA256 hash (a one-way fingerprint, not the file) — and only when you explicitly use the manual hash-check option **and** have set a VirusTotal API key. Everything else runs and stays 100% local.

**Q: How do I get a VirusTotal API key?**
Create a free account at [virustotal.com](https://www.virustotal.com), go to your profile → **API Key**, and paste it in when prompted from Menu Option 16, or hardcode it at the top of the script. See the comment block at the top of the `.ps1` file for details.

**Q: A check came back `[HIGH]` — am I infected?**
Not necessarily. It means the file/entry matched multiple risk heuristics (e.g., unsigned + running from a temp folder + suspicious command pattern). Investigate the specific file: check its signature, where it came from, and consider a VirusTotal lookup before assuming the worst.

**Q: Can I trust a script that was built with AI assistance?**
The code is fully open and readable — nothing is hidden or obfuscated. Read through it, run it in a VM if you want to be extra careful, and judge it on what it actually does rather than how it was written. That's true of any script you download, AI-assisted or not.

**Q: Why does it need Administrator to fully work?**
Several Windows APIs (service enumeration, some scheduled task details, certain network/process info) restrict what non-elevated processes can see. The tool works without admin, just with reduced visibility — it tells you exactly which checks are limited.

**Q: Can I contribute / suggest a feature?**
Yes — open an issue or a pull request. See below.

---

## Contributing

Issues and pull requests are welcome. If you're proposing a new check, please keep it consistent with the project's core rule: **read-only, evidence-only, no automatic remediation.** That boundary is intentional and won't change.

---

## License

Released under the [GNU General Public License v3.0](LICENSE).

In short: anyone can use, study, modify, and redistribute this project — including commercially — but if they distribute a modified version, they must also release their source code under GPL-3.0 and keep the original copyright/license notices intact. This keeps the project and any forks of it permanently open.

If you build on this project, please keep the attribution notice at the top of the script and mention that your version is based on the BloodFallen Forensic Triage Toolkit.

## Safety Philosophy

- Read-Only Inspection
- No Registry Modifications
- No File Deletions
- No Automatic Cleanup
- Evidence Collection Only
- User Makes The Final Decision

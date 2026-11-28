# EZTech Cybersecurity Toolkit

A practical collection of defensive cybersecurity, system-auditing, incident-response, and vulnerability-management utilities maintained by EZTech LLC.

> **Authorized use only.** Run these tools only on systems and networks you own or are explicitly authorized to assess.

## Toolkit

- `windows/` — Windows security auditing and host triage
- `linux/` — Linux security auditing and host triage
- `network/` — network inventory, exposure, and TLS checks
- `incident-response/` — hashing, IOC matching, and evidence triage
- `log-analysis/` — authentication and security-log analysis

## Requirements

Most Python tools require Python 3.10+ and use only the standard library. PowerShell scripts target PowerShell 5.1+ unless noted. Bash utilities target common GNU/Linux distributions.

## Safety philosophy

These scripts are designed to be read-only or minimally invasive by default. They favor inventory, validation, detection, and reporting rather than exploitation or persistence.

## Quick examples

```powershell
powershell -NoProfile -File .\windows\windows-security-audit.ps1
```

```bash
python3 incident-response/file-integrity.py /etc --output baseline.json
python3 network/tls-audit.py example.com
```

## Handling audit output

Audit reports and integrity baselines can contain account names, internal addresses, file paths, and other sensitive inventory. Store them in an access-controlled directory outside the repository; do not commit real customer or production reports. On Linux, set `umask 077` before running tools that write reports. On Windows, use a directory with restricted NTFS permissions. Review and redact reports before sharing them, and retain only what is necessary for the authorized assessment.

Run scripts without elevated privileges first. Elevate only when a documented check requires it and the assessment scope permits it. Review downloaded scripts before execution and follow your organization's PowerShell execution policy; do not bypass it as a routine prerequisite.

## Contributions

Keep additions documented, scoped for legitimate administrative/security use, and safe by default.

## License

MIT. See `LICENSE`.

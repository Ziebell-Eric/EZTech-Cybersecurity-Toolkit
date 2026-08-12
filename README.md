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
powershell -ExecutionPolicy Bypass -File .\windows\windows-security-audit.ps1
```

```bash
python3 incident-response/file-integrity.py /etc --output baseline.json
python3 network/tls-audit.py example.com
```

## Contributions

Keep additions documented, scoped for legitimate administrative/security use, and safe by default.

## License

MIT. See `LICENSE`.

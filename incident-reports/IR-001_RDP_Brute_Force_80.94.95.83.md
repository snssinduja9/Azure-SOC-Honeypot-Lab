# Incident Report IR-001: RDP Brute-Force Attack from 80.94.95.83

| Field | Detail |
|---|---|
| **Incident ID** | Sentinel Incident #3 |
| **Detection rule** | Brute Force - Multiple Failed Logons from Single IP (custom scheduled analytics rule) |
| **Severity** | Medium |
| **Status** | Closed |
| **Classification** | True alert / True Positive (suspicious activity, unsuccessful) |
| **Analyst** | Sinduja Natesan Subramanian |
| **Affected host** | CORP-NET-EAST-1 (Azure Windows 10 honeypot VM) |
| **Source IP** | 80.94.95.83 |
| **MITRE ATT&CK** | T1110.001 Brute Force: Password Guessing (Tactic: Credential Access) |

---

## 1. Summary

An automated brute-force attack from **80.94.95.83** made **16,813 failed logon attempts** against the honeypot VM **CORP-NET-EAST-1** over about 9.5 hours. The attacker cycled through a wordlist of default account names. None of the usernames existed on the host, and there were **no successful logons** from the source IP. **No compromise occurred.**

## 2. Timeline (UTC)

| Time | Event |
|---|---|
| 2026-10-07 16:03:29 | First failed logon (Event ID 4625) from 80.94.95.83 |
| 2026-10-07 16:03 – 2026-10-08 01:33 | Continuous attempts at ~1,770/hour (~30/minute) |
| 2026-10-08 01:33:19 | Last failed logon from 80.94.95.83 |
| 2026-10-13 | Analytics rule deployed with a 14-day lookback; alerts covering 53 ten-minute windows grouped into Incident #3 (later re-runs added duplicate alerts, 150 total, until the lookback was reduced) |
| 2026-10-13 | Incident assigned, investigated, enriched and closed |

> Note: Detection was retrospective. The analytics rule was created after the attack, and its 14-day lookback surfaced the historical activity. In production the rule runs hourly, so a similar attack would be flagged within an hour.

## 3. Scope and Evidence

**Failed logons (Event ID 4625) from 80.94.95.83:**

| Metric | Value |
|---|---|
| Total attempts | 16,813 (~65% of all 25,960 failed logons collected from 11 unique IPs) |
| Duration | ~9.5 hours |
| Rate | ~30 attempts per minute (automated tool) |
| Logon type | 3 (Network, RDP with NLA / NTLM) |
| Usernames tried | ADMIN, USER, BACKUP, ADMINISTRATOR, ADMINISTRADOR, SYSTEM, Test |
| SubStatus | 0xc0000064 only (username does not exist) |

**Interpretation:**
- The usernames are a generic wordlist of default or common account names, including localized variants ("Administrador"). This points to an untargeted, mass-scanning tool.
- SubStatus **0xc0000064** on every attempt means the attacker **never found a valid username**. The chance of success was negligible.
- Alert count (53 alerts × 10-minute windows ≈ 9 hours) matches the attack duration in the raw logs.

**KQL used (scope):**
```kql
SecurityEvent
| where EventID == 4625 and IpAddress == "80.94.95.83"
| summarize Attempts = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
    Usernames = make_set(TargetUserName, 15), SubStatus = make_set(SubStatus)
```

## 4. Impact Assessment

**Successful logons (Event ID 4624) from 80.94.95.83: none.**

```kql
SecurityEvent
| where EventID == 4624 and IpAddress == "80.94.95.83"
```

A detection rule for "successful logon after repeated failures" (T1110 / T1078) also returned no results across the dataset. Across all collected data, the only successful logons came from the lab administrator's own IP.

**Impact: no evidence of successful access by the attacker in the collected Windows Security logs.** (Scope: the honeypot collected Windows Security events only, with no EDR or process telemetry, so the conclusion is based on authentication evidence.)

## 5. Threat Intelligence Enrichment

**AbuseIPDB (checked 2026-10-13):**

| Field | Value |
|---|---|
| Abuse confidence | **100% (Critical)** |
| Reports | 8,652 reports from 351 distinct sources |
| First reported | 26 Jan 2023; most recent report within the last 2 hours |
| ISP / Usage type | UNMANAGED LTD, Data Center/Web Hosting/Transit |
| ASN | AS204428 |
| Geolocation | Timișoara, Romania (hosting location, not necessarily the operator's location) |
| Top categories | Hacking, Port Scan, Brute-Force, Bad Web Bot, Web App Attack |
| Notable | Many reports from other RDP honeypots (port 3389) logging the same username pattern ("administr") |

**VirusTotal (last analysis ~2026-10-11):**

| Field | Value |
|---|---|
| Detections | **13/92** vendors flagged as malicious (plus 3 suspicious: AlphaSOC, Gridinsoft, Guardpot) |
| Community score | -1 |
| Notable vendors | GreyNoise (Malicious, tracks internet-wide scanners), Fortinet, BitDefender, Sophos, Forcepoint |
| Network | 80.94.95.0/24, AS204428 (SS-Net), Romania |

> The vendor labels vary (Malware, Phishing, Malicious) because each vendor uses its own reputation categories. They don't mean this IP was used for phishing in this incident. A moderate VirusTotal ratio for an IP is normal; the AbuseIPDB report history and the GreyNoise "Malicious" verdict give stronger evidence of scanning and brute-force behaviour.

**Assessment:** a known, long-running piece of malicious infrastructure on rented hosting, running internet-wide RDP scanning and brute-force campaigns. The activity was opportunistic, not targeted at this organization.

## 6. Verdict

**True Positive (suspicious activity, unsuccessful).** Confirmed automated RDP brute-force attempt from a known malicious IP. No compromise.

## 7. Recommendations

1. **Block** 80.94.95.83 at the Network Security Group / firewall (consider blocking AS204428 if business needs allow).
2. **Remove direct internet exposure of RDP (3389):** restrict the NSG to known source IPs, or use Azure Bastion / VPN / Just-In-Time VM access.
3. **Enforce an account lockout policy** and strong, unique passwords; **enable MFA** for remote access.
4. **Rename or disable default accounts** (e.g. Administrator) to defeat wordlist-based guessing.
5. **Detection improvement:** add a longer-window rule (e.g. 30+ failures in 24 hours) to catch low-and-slow attackers. 5 of the 11 source IPs never crossed the 10-in-10-minutes threshold (peak rates of 1–4 attempts per 10 minutes), so they generated no alerts.

## 8. Lessons Learned

- Threshold-based detection catches noisy brute force well but misses low-volume attackers, so layered thresholds are needed.
- SubStatus codes separate username guessing (0xc0000064) from attacks on valid accounts (0xc000006a) and directly drive incident priority.
- Threat intelligence context (100% confidence, 351 reporters, hosting ASN) quickly confirms a mass campaign rather than a targeted attack.

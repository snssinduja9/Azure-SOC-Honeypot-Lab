# Azure SOC Honeypot Lab (Microsoft Sentinel, KQL, incident response)

I put a Windows VM on the internet with the firewall off, waited to see who would try to break in, and then investigated it the way an L1 SOC analyst would. Logs went into Microsoft Sentinel, I wrote my own detection rules in KQL, and I triaged every incident they raised.

![Attack map](screenshots/01-attack-map.png)

## The short version

In about 24 hours the VM got **25,960 failed logins from 11 IP addresses**. Most of it came from one IP in a data center (80.94.95.83), which made almost 17,000 attempts on its own, around 30 per minute, all night.

I wrote two detection rules, got 7 incidents out of them and closed all 7. The biggest one I investigated properly and wrote up as an incident report. Nobody got in: every successful login in the logs was mine.

The part I learned most from was finding the weak spots in my own rules. Five IPs never set off an alert, and one setting I chose made the same attack alert over and over. Both are written up below.

## My contribution

**From the tutorial (Josh Madakor's Azure SOC lab):** the VM deployment, sending logs to Log Analytics, connecting Sentinel, the GeoIP watchlist and the attack map.

**My own work, built on top of that:**
- **Detection rules:** wrote both analytics rules, then rewrote Rule B after finding it didn't check the order of events
- **Investigation:** triaged all 7 incidents and did a full investigation of the biggest one, including SubStatus analysis, the impact check and threat intel lookups
- **Tuning:** found the 5 IPs my threshold missed, and fixed the duplicate alerts caused by my own lookback setting
- **Documentation:** MITRE ATT&CK mapping and the incident report (IR-001)

## Contents

- [Results](#results)
- [How the lab is set up](#how-the-lab-is-set-up)
- [How I built it](#how-i-built-it)
- [Detection rules](#detection-rules)
- [KQL queries I used to investigate](#kql-queries-i-used-to-investigate)
- [Investigating the biggest incident (IR-001)](#investigating-the-biggest-incident-ir-001)
- [Threat intel and MITRE ATT&CK](#threat-intel-and-mitre-attck)
- [What I learned](#what-i-learned)
- [Gaps I found and what I'd fix](#gaps-i-found-and-what-id-fix)
- [What I'd do in a real environment](#what-id-do-in-a-real-environment)
- [Repo layout](#repo-layout)
- [Next steps](#next-steps)
- [Safety and cost](#safety-and-cost)

## Results

| | |
|---|---|
| Collection period | about 24 hours, 7–8 October 2026 |
| Failed logins (Event ID 4625) | 25,960 |
| Source IPs | 11 |
| Top attacker | 80.94.95.83, 16,813 attempts (about 65% of everything) |
| Fastest burst | 304 attempts in 10 minutes, from 62.238.86.212 |
| Successful logins from attacker IPs (4624) | 0. Every network/RDP login in the logs came from my own IP |
| Incidents | 7 raised, 7 triaged |
| IPs my rule missed | 5 of 11 |

These numbers only cover my one-day window, so they're a snapshot, not a measure of how much the internet attacks Azure in general.

## How the lab is set up

```
          Attackers on the internet
                    │  RDP / NTLM login attempts
                    ▼
   Network Security Group (allow everything in, on purpose)
                    │
                    ▼
   Windows 10 VM "CORP-NET-EAST-1" (Windows Firewall off)
                    │  Security events: 4625 failed, 4624 success
                    ▼
   Azure Monitor Agent + Data Collection Rule
                    │
                    ▼
   Log Analytics workspace ──► Microsoft Sentinel
                                 ├─ KQL hunting
                                 ├─ GeoIP watchlist + attack map
                                 └─ Analytics rules ─► incidents ─► my triage
                                                                     │
                                                    AbuseIPDB / VirusTotal
                                                                     │
                                                       classification + report
```

The Azure side:

| | |
|---|---|
| Resource group | `RG-SOC_Lab` |
| VM | Windows 10 Enterprise, `Standard_D2s_v4`, hostname `CORP-NET-EAST-1` |
| Region | East US 2 |
| Logs | Azure Monitor Agent → Data Collection Rule → Log Analytics |
| SIEM | Microsoft Sentinel |

To be clear, opening every port and turning the firewall off was only for the experiment. You'd never do this on a real machine.

## How I built it

**The honeypot.** I created the VM, added an NSG rule that allows all inbound traffic, then logged in and turned off Windows Firewall for all three profiles. By the time my logs were flowing, bots had already found it.

**Getting the logs out.** I set up the Azure Monitor Agent with a Data Collection Rule to send Windows Security events to a Log Analytics workspace. I mainly cared about two event IDs: **4625** (failed login), which tells you who's trying and which usernames, and **4624** (successful login), which tells you if anyone got in. Before building anything else I checked the events were actually arriving.

**Sentinel and the map.** I turned on Sentinel for the workspace, imported a GeoIP watchlist and joined it to the failed logins to draw the attack map. The map looks good, but I only treat the locations as rough. More on that in [What I learned](#what-i-learned).

**Rules and triage.** I wrote two scheduled analytics rules, worked through all 7 incidents they created, and picked the biggest one for a full investigation.

## Detection rules

![Analytics rules](screenshots/02-analytics-rules.png)

### Rule A: lots of failed logins from one IP

The idea is simple. If one IP fails to log in 10 or more times in 10 minutes, that's not someone who forgot their password.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count(), Usernames = make_set(TargetUserName, 20)
    by IpAddress, Computer, bin(TimeGenerated, 10m)
| where FailedAttempts >= 10
```

It groups failed logins by IP, by machine and by 10-minute block, and alerts on any group with 10 or more. I added the list of usernames so whoever picks up the alert can see straight away what was being tried.

- Runs every hour, severity Medium, mapped to **T1110 Brute Force**
- Result: 7 incidents from 6 IPs

The weakness is that anyone going slower than 10 attempts per 10 minutes never shows up. In my data, 5 IPs did exactly that.

### Rule B: a successful login right after a lot of failures

This is the alert you really don't want to see, because it means the brute force may have worked.

```kql
let Successes = SecurityEvent
    | where EventID == 4624 and LogonType in (3, 10)
    | project SuccessTime = TimeGenerated, Account, IpAddress, Computer, LogonType;
let Failures = SecurityEvent
    | where EventID == 4625
    | project FailTime = TimeGenerated, IpAddress, Computer;
Successes
| join kind=inner Failures on IpAddress, Computer
| where FailTime between ((SuccessTime - 1h) .. SuccessTime)
| summarize FailedBefore = count(), FirstFailure = min(FailTime)
    by SuccessTime, Account, IpAddress, Computer, LogonType
| where FailedBefore >= 10
```

For each successful network or RDP login, it looks at the hour before it and counts failures from the same IP on the same machine. Ten or more and it alerts.

- Runs every hour with a 2-hour lookback, severity High, mapped to **T1110** and **T1078 Valid Accounts**
- Result: nothing. No attacker IP ever logged in.

My first version of this rule was sloppier. It flagged any successful login from an IP that had 10+ failures *at any point*, without checking that the failures came first. Something could have happened days apart and it would still have matched. The version above fixes that.

All the queries are in [`kql/queries.kql`](kql/queries.kql).

## KQL queries I used to investigate

Top attackers, which is where I started:
```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by IpAddress
| order by Attempts desc
```
![Top attackers query](screenshots/04-top-attackers-kql.png)

Why the logins failed. This one turned out to matter a lot (see IR-001 below):
```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress, TargetUserName, SubStatus
| order by Attempts desc
```

Did a particular IP ever get in:
```kql
SecurityEvent
| where EventID == 4624 and IpAddress == "80.94.95.83"
```

Attack timeline in 10-minute blocks:
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by bin(TimeGenerated, 10m), IpAddress
| order by TimeGenerated asc
```

Which IPs my Rule A never caught. Anything with MaxIn10Min under 10 slipped through:
```kql
SecurityEvent
| where EventID == 4625
| summarize c = count() by IpAddress, bin(TimeGenerated, 10m)
| summarize TotalAttempts = sum(c), MaxIn10Min = max(c) by IpAddress
| order by TotalAttempts desc
```

## Investigating the biggest incident (IR-001)

![Incident details](screenshots/03-incident-details.png)

Incident #3 was the obvious one to dig into: 53 ten-minute alert windows, all from 80.94.95.83.

**How big was it?** 16,813 failed logins between 16:03 UTC on 7 October and 01:33 UTC on 8 October. That's about 9.5 hours at roughly 30 attempts a minute without a break. Definitely a script, not a person.

**What was it trying?** Only seven usernames: `ADMIN`, `USER`, `BACKUP`, `ADMINISTRATOR`, `ADMINISTRADOR`, `SYSTEM`, `Test`. These are default account names, and "Administrador" is the Spanish/Portuguese version, so it looks like a generic wordlist built to work on machines anywhere. Nothing about it was aimed at my VM in particular.

**Did those accounts even exist?** No, and this was the most useful thing I found. Every single attempt had SubStatus `0xc0000064`, which means "this username doesn't exist." If I'd seen `0xc000006a` instead (real username, wrong password), I'd have taken it much more seriously, because then the attacker only needs the password. Here they never found a real account.

**Did anyone get in?** I searched for 4624 events from this IP and got nothing back. I also went through every network/RDP login in the dataset, and all of them were from my own IP. So there's no sign of attacker access in the logs. I should be honest about the limits: the VM only sent Windows Security events, with no EDR or process data, so this conclusion is based on login evidence only.

![No 4624 from attacker](screenshots/05-no-compromise-4624.png)

**Who is this IP?** I checked it on 13 October:
- **AbuseIPDB** gave it a 100% abuse score, with 8,652 reports from 351 different people since January 2023, and it was still being reported that day. A lot of those reports came from other people's RDP honeypots, seeing the same thing I saw.
- **VirusTotal** had 13 of 92 vendors flagging it, including GreyNoise, which specifically tracks internet-wide scanners.
- It sits on data center hosting (AS204428). AbuseIPDB places it in Romania, while my GeoIP watchlist said the Netherlands.

![AbuseIPDB result](screenshots/06-abuseipdb.png)

**Verdict:** true positive, unsuccessful. It was a real attack from a known bad IP, it just didn't work. I closed it with notes, and closed the other six the same way after checking each one.

![Incident closed](screenshots/07-incident-closed.png)

The full write-up is in [`incident-reports/IR-001_RDP_Brute_Force_80.94.95.83.md`](incident-reports/IR-001_RDP_Brute_Force_80.94.95.83.md).

## Threat intel and MITRE ATT&CK

13 out of 92 on VirusTotal doesn't look that scary at first. But most of those vendors don't track scanning IPs at all, and the one that does (GreyNoise) flagged it. AbuseIPDB had years of history and hundreds of reporters. Put that next to my own logs (17,000 attempts at 30 a minute) and there wasn't much doubt. I didn't trust any one source on its own, and I don't think you should.

| Technique | Where it shows up |
|---|---|
| T1110 Brute Force | Rule A |
| T1110.001 Password Guessing | IR-001, the wordlist of default names |
| T1078 Valid Accounts | Rule B. This is what a successful brute force would look like. It didn't happen here. |

## What I learned

**It doesn't take long.** I expected some attacks, but not almost 7,000 in the first 8 hours and close to 26,000 by the next morning. Bots are scanning for open RDP all the time.

**Look at why a login failed, not just how many times.** It's easy to look at 4625 and just count. SubStatus told me whether the attacker even had a real username, and that changed how worried I needed to be.

**My threshold missed people.** Five of the 11 IPs never went above 4 attempts in any 10-minute window. Two of them still made 63 and 89 attempts over the day. A short-window rule is fine for noisy attackers, but the patient ones walk straight past it.

**I caused my own duplicate alerts.** To catch the attacks that had already happened, I set Rule A to look back 14 days. Then it ran every hour and re-found the same activity each time, and incident #3 went from 53 alerts to 150. Cutting the lookback back to match the schedule fixed it. This is the kind of thing that makes analysts hate a rule, so I'm glad I ran into it here.

**Don't trust the map too much.** My watchlist said Netherlands, AbuseIPDB said Romania, for the same IP. And it's a hosting server anyway, so neither tells you where the person actually is.

**Cloud setup takes patience.** Several VM sizes just wouldn't deploy on the free trial. Some had no capacity in my zone, and the newer v6 sizes need NVMe disks, which the Windows 10 image doesn't support. On the query side, my first scoping query came back with 0 results because I'd left the placeholder text where the IP should go. Small mistake, but it taught me to check the query before believing an empty result. The time range catches people out too: with the VM stopped, "last 24 hours" shows nothing.

**Public vs. private IPs.** My laptop's own IP (192.168.x.x) never showed up in the VM's logs, only my home router's public IP. That's NAT. It made me realise that in a real company, a public IP in an alert won't tell you which laptop it was; you'd need the firewall or NAT logs for that.

## Gaps I found and what I'd fix

| Problem | Fix |
|---|---|
| Slow attackers stay under the 10-in-10-minutes threshold | A second rule over 24 hours, something like 30+ failures a day |
| A long lookback caused repeat alerts | Keep the lookback in line with the schedule (done) |
| Rule B v1 didn't check that failures came before the success | Rule B v2 only counts failures in the hour before the login (done) |
| Looking up every IP by hand is slow | A Logic Apps playbook to check the IP and add the result to the incident |
| I can only see logins, not what happens on the machine | Add Defender for Endpoint or Sysmon |

## What I'd do in a real environment

- Don't expose RDP to the internet. Use Azure Bastion, a VPN or Just-In-Time access.
- Lock the NSG down to the sources and ports you actually need.
- Use strong unique passwords, MFA and an account lockout policy.
- Rename or disable default accounts like Administrator, since that's exactly what these wordlists go after.
- Run both short and long window brute-force rules, plus a success-after-failure rule.
- Use threat intel as evidence, not as an automatic block list. Blocking a whole ASN can hurt real users too.

## Repo layout

```
Azure-SOC-Honeypot-Lab/
├── README.md
├── kql/queries.kql
├── incident-reports/IR-001_RDP_Brute_Force_80.94.95.83.md
└── screenshots/ (7 images)
```

## Next steps

- [ ] Add the 24-hour low-and-slow rule
- [ ] Build a Logic Apps playbook for automatic IP lookups
- [ ] Lock the NSG down and compare attack volume before and after
- [ ] Onboard the VM to Microsoft Defender for Endpoint and investigate simulated attacks with Atomic Red Team
- [ ] Write IR-002 on the second biggest attacker (62.238.86.212)

## Safety and cost

I stop the VM whenever I'm not using it, with auto-shutdown as a backup. The VM has a long unique password, I turned off drive sharing in my RDP client so nothing on my laptop was reachable from the VM, and I never signed into anything personal on it. My own IP and email are blacked out in the screenshots. One thing I didn't know at first: a stopped VM still costs a little for the disk and public IP until you delete them.

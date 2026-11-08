# Detection engineering methodology

How every rule in this repository is built, tested and maintained.

## 1. Start from a hypothesis, not from a log

Each rule answers one question: *"If an attacker performed technique X, what would I see, and where?"*

| Question | Example (shadow copy deletion) |
|---|---|
| Which technique? | T1490 — Inhibit System Recovery |
| Why would an attacker do it? | Ransomware removes restore points before encrypting |
| Which telemetry shows it? | Process creation (Sysmon EID 1 / Security 4688 with command line) |
| What is the observable? | `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit ... recoveryenabled no` |

## 2. Check the telemetry exists

A rule is useless if the data is not collected. Before writing it, confirm:

- the log source is enabled (e.g. command-line auditing for 4688, Sysmon config, auditd rules);
- the fields used by the rule are present and parsed in the SIEM;
- the retention period is long enough for investigation.

## 3. Write the rule for behaviour, not for a tool

- Match on what the technique **must** do, not on a tool name an attacker can rename.
- Prefer stable identifiers: `OriginalFileName` over `Image`, well-known SIDs (`S-1-5-32-544`) over localised group names.
- Document false positives honestly in `falsepositives` — the analyst who triages the alert will read them.

## 4. Prove it with tests

Every rule ships with two kinds of synthetic events:

- **true positives** — realistic attack variants (short flags, renamed binaries, encoded payloads);
- **true negatives** — the closest *benign* look-alikes (listing shadow copies instead of deleting them, reading history instead of wiping it).

CI refuses any rule that misses an attack sample or fires on a benign one.

## 5. Assign a level that reflects triage urgency

| Level | Meaning for the analyst |
|---|---|
| **high** | Rarely benign. Investigate immediately, consider containment. |
| **medium** | Suspicious in context. Investigate within the shift, check the parent process and the user. |
| **low / informational** | Hunting signal, useful in correlation, not alerted alone. |

## 6. Tune after deployment

1. Deploy in *monitoring* mode and measure the alert volume against the baseline.
2. For each false positive, add a **narrow** filter (specific parent process, path, or account) — never a broad one that blinds the rule.
3. Add the false positive as a new `no_match` test so it never comes back.
4. Review rules regularly against ATT&CK updates (this repo is aligned with v19).

## 7. Triage checklist when a rule fires

- Who? User account, privileges, is it a service account?
- What? Full command line, parent and child processes.
- Where? Host role (server, workstation, DC), exposure.
- When? Business hours, linked to a change ticket?
- What happened next? Network connections, new files, logons from the same account.

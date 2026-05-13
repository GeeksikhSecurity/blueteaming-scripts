# The Operational Discipline Manifesto

> Over 90% of security problems are due to lack of operational discipline.

## The premise

Read the Verizon DBIR. Read M-Trends. Read any breach retrospective written by someone who was actually in the room. The cybersecurity industry constantly reinvents itself — new categories, new acronyms, new buzzwords, new vendor booths at RSA — but the root causes of incidents stay almost unchanged year over year:

- Misconfigurations
- Unpatched systems
- Third-party risk
- Identity mismanagement
- Flat networks, poor segmentation
- A handful of other operational oversights

Companies don't get breached by novel, cutting-edge attacks. They get breached by **the same fundamental problems, over and over**.

This is not a coincidence. The root cause is operational-discipline failure — the inability to consistently implement, monitor, and enforce the basics at scale.

The concept and term comes from Yaron Levi, CISO at Dolby, and was surfaced for me by [Venture in Security](https://substack.com/@ventureinsecurity). It continues to surprise me that "lack of operational discipline" isn't a generally accepted root-cause category alongside the more glamorous "advanced persistent threat" framing.

## Why this matters for detection engineering

If 90% of incidents come from operational-discipline failure, then 90% of detection engineering ROI lives in detecting those failures **before** an attacker does. Yet most detection-engineering effort is poured into:

- Threat-actor TTP coverage (MITRE ATT&CK alignment)
- IOC ingestion pipelines
- ML-driven anomaly detection
- Threat-intel-driven hunts

These are valuable. But they are downstream of the gap. They detect the attacker who has already entered. They do not detect the misconfiguration that let them in.

This pack inverts the priority. Every detection here targets a hygiene gap, not a TTP. Specifically:

1. **Standing privilege** — accounts with admin rights they don't need, all the time.
2. **Stale identities** — accounts that should have been deprovisioned but weren't.
3. **MFA gaps** — privileged accounts without strong second factors.
4. **Public exposure** — buckets, endpoints, and resources accidentally open to the internet.
5. **Unpinned supply chain** — GitHub Actions and dependencies referenced by mutable tags.
6. **Disabled guardrails** — branch protection off, secret scanning off, Dependabot off.
7. **Insecure defaults left in place** — classic admins, root keys, public access blocks unset.

## The "lack of operational discipline" framing in practice

Detection vs. discipline:

| Detection-centric question | Discipline-centric question |
| --- | --- |
| Did we see the attack? | Did the attack path exist? |
| Can we respond fast? | Could we have removed the path? |
| Which TTPs are we missing? | Which controls aren't enforced? |
| What's our MTTR? | What's our drift rate? |

Both questions matter. But organizations under-invest in the right-hand column because it's boring, it has no vendor pitch, and it doesn't generate dashboard-worthy graphs. The Verizon DBIR is telling us — relentlessly — that the right-hand column is where the loss-event probability mass actually lives.

## A word on the framing

This pack will not catch a novel zero-day. It will not stop a nation-state. It will catch the misconfigured S3 bucket, the standing Global Administrator, the GitHub Action pinned to `@main`, the IAM access key from 2019, the conditional access policy that was never deployed.

That is, statistically, what is going to hurt you.

## References

- Verizon, _2024 Data Breach Investigations Report_. https://www.verizon.com/business/resources/reports/dbir/
- Mandiant, _M-Trends 2024_. https://www.mandiant.com/m-trends
- Levi, Y. — public talks and writing on operational discipline as the dominant root cause.
- Venture in Security — _Why operational discipline is the unsexy answer to most security problems_. https://substack.com/@ventureinsecurity

## Related notes

- [Detection Engineering Ideas](./detection-engineering-ideas.md) — concrete detections this pack should grow into.

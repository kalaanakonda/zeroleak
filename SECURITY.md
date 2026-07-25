# Threat model & security notes

Zeroleak's claim is narrow and specific: it eliminates **pre-exam paper leaks** —
the class of attack where the paper is stolen, photographed, or sold in the days
or weeks before the exam. It does this by ensuring the paper does not exist until
T‑0. This document is honest about what that does and does not buy.

## The core property

> Before T‑0, the number of people (or machines) that know the paper is **zero**.

The seed that determines the paper is:

```
seed = SHA-256( ceremony_secret  +  drand_beacon_value )
```

- `ceremony_secret` is reconstructed from **5 of 9** fragments via Shamir secret
  sharing. In the live cluster (`/cluster`) it is produced by distributed key
  generation: no single process ever holds it; it exists only when ≥5 final
  shares are combined at T‑0.
- `drand_beacon_value` comes from a public randomness beacon (~20 independent
  organizations) that produces a fresh value every 30 seconds. The round used
  must be produced *after* the fairness commitment was published, so it cannot
  be known in advance — not even by someone holding the ceremony secret.

Both inputs must be present, and both are unavailable before T‑0.

## Attacks considered

| Attack | Outcome |
|--------|---------|
| Steal the pre-exam paper | Nothing exists to steal before T‑0. |
| Bribe the paper-setter | No human sets the paper; a seed does, at T‑0. |
| Compromise the server / read all code | Code is public by design; it holds no secrets. Seeds and fragments are runtime-only. |
| Steal one official's fragment | Worthless — 4 fragments reveal nothing; you need 5, from 5 institutions. |
| Fake devices joining the ceremony | Rejected: every ceremony message is signed by a registered per-official key. |
| Predict / rig the beacon | The beacon value does not exist until T‑0 and is produced by ~20 independent orgs. |
| Swap the paper or question bank | Caught by public commit–reveal: anyone recomputes the receipt after the exam. |
| Tamper with the audit log | Hash-chained; altering any past entry breaks every later link, visibly. |
| Leak a copy during the exam | Traced to center/room/seat via invisible watermark; and a during-exam copy is far less valuable than the (now impossible) pre-exam one. |

## Attacks NOT solved by this prototype

Being honest about the boundary:

- **A camera pointed at a screen.** No software stops the "analog hole." The
  design makes such a photo (a) impossible before the exam and (b) traceable
  during it — but it does not make screens unphotographable.
- **Total infrastructure sabotage.** An attacker with full control of every
  server can *disrupt* an exam (a visible, reschedulable denial of service) —
  they still cannot extract a paper that does not exist. Leak vs. sabotage are
  different harms; this design converts the former into the latter.
- **Impersonation, in-hall cheating, center logistics, power/network failure.**
  Separate problems. A production system pairs this with existing identity rails
  (e.g. Aadhaar/DigiLocker) and offline fallback (pre-staged encrypted paper +
  key broadcast at T‑0).

## Prototype limitations (do not deploy as-is)

- In-memory state, no persistence, no authentication, no rate limiting.
- The nine "officials" run as nine processes on one host, not nine independent
  machines. The cryptography is real; the deployment topology is not.
- The single-server `/` ceremony deals the secret on one server (a convenience
  for the verifiable demo); the `/cluster` view is the dealerless version.
- Question bank is a 21-item demo, not a blueprint-balanced production bank.

## Reviewing this yourself

The in-browser verifier on `/` re-derives every claim on your own device. The
code is deliberately small and dependency-free so it can be read end to end.
Found a hole? That is the point — open an issue. An adversarial review of an
earlier build found and fixed 18 real issues; that process should continue in
public.

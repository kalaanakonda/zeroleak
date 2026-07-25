# Zeroleak — the exam paper that cannot leak

> A working prototype of an exam-delivery system where the question paper **does
> not exist until the exam begins** — so there is nothing to steal, photograph,
> or bribe out of a strongroom in the weeks beforehand.

Motivated by India's NEET paper leaks (e.g. Hazaribagh, 2024), where the entire
crime lives in the gap between *"the paper exists"* and *"the exam starts."*
Zeroleak shrinks that gap to zero.

**This is a concept prototype, not production software.** It is meant to be read,
run, and argued with. Everything security-relevant is observable and, where
possible, independently verifiable in your own browser — because the whole point
is *verify, don't trust*.

---

## The idea in one paragraph

A large bank of vetted questions is public (knowing all of them is just knowing
the syllabus). The actual paper is chosen at exam time by a random **seed** that
is *born* at T‑0 and derived from two independent sources — a **5‑of‑9 official
key ceremony** and a **public randomness beacon** ([drand](https://drand.love)).
Before T‑0 the seed does not exist anywhere, so neither does the paper. Every
center gets the same questions in a different order with an invisible watermark,
so any leaked copy traces back to its source. A commitment published before the
exam, plus full disclosure after, lets anyone verify nothing was rigged.

## Run it

Zero dependencies. Node 18+.

```bash
node server.js
# → http://localhost:4870
```

Then open the pages:

| Page | What it shows |
|------|---------------|
| `/`            | **Glass room** — schedule an exam, watch centers unlock at T‑0, and see your browser independently re-verify 7 cryptographic claims |
| `/cluster`     | **Live cluster** — nine *real, separate OS processes* run a no-dealer key ceremony, each streaming its own terminal |
| `/infographic` | **How it works** — animated, scroll-through explainer with per-term tooltips |
| `/present`     | **Presentation** — slide deck (English / everyday Hindi toggle) |
| `/source`      | **Read the source** — every file, served by the app itself |

## What's real vs. simulated

Honesty matters in a project about integrity. So, plainly:

**Real:**
- Shamir secret sharing and Lagrange reconstruction over GF(2²⁵⁶−189)
- Distributed key generation across nine genuinely separate OS processes
  (`/cluster`), where the coordinator only relays RSA-encrypted fragments and
  never sees the key
- Live [drand](https://drand.love) beacon fetch, mixed into the seed, with a
  freshness rule (the round used must be produced *after* the commitment)
- SHA-256 commit–reveal and a hash-chained audit ledger
- In-browser re-verification: your device recomputes the receipt, re-checks
  every fragment commitment, re-runs the Shamir math, re-derives the seed,
  rebuilds all papers from the seed, and re-validates the ledger chain
- Zero-width-character watermarking and tracing

**Simulated / out of scope for this prototype:**
- A production deployment would run the nine parties on nine independent
  machines in nine institutions, not nine processes on one host
- No authentication, rate limiting, or persistence (state is in-memory)
- The question bank is 21 demo items, not a blueprint-balanced bank of thousands
- Camera-of-a-screen leaks, impersonation, and center logistics are separate
  problems this prototype does not solve

See [SECURITY.md](SECURITY.md) for the full threat model and the attacks this
design does and does not defend against.

## Why publishing the code is safe

The secrets are never *in* the code. The paper is decided by the officials'
fragments (generated fresh at runtime), the drand value (which does not exist
until T‑0), and the seed derived from them. None is a constant in this
repository. This is [Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle):
a real system stays secure even when its design is fully public — only the key
stays secret. Open source is not a compromise here; it is what makes the
browser-side verification possible at all.

## Architecture

```
server.js        Coordinator + HTTP. Serves pages, runs the single-server
                 "glass room" ceremony, and orchestrates the live cluster.
official.js      One real process per official. Runs distributed key
                 generation; holds only its own fragment.
questionbank.js  Public vetted question bank (demo size).
public/          The five views (glass room, cluster, infographic,
                 presentation, source viewer) + CC0 images.
```

## Credits

Presentation images are public-domain / CC0 via Wikimedia Commons, the Library
of Congress, NASA, and the FBI — see [public/img/CREDITS.md](public/img/CREDITS.md).

## License

[MIT](LICENSE) — use it, fork it, build a real one. That is the goal.

# How tundra was built with an AI agent

I chose the problem: a user-space TCP/IP stack, to show low-level C++ and networking. I also set the
constraints: interoperate with Linux, measure the trade-offs, build everything in Docker. Claude Code
drafted the spec and wrote the code in small steps. This page describes what kept that work checkable,
and what the checks caught.

## Context first

- **A spec before code.** [`docs/design.md`](design.md) was the first commit. It fixed the scope (and what is
  out of scope), the architecture, the four checksum variants, and the test layers that would hold the code
  to it.
- **Invariants an agent must not break** ([`AGENTS.md`](../AGENTS.md)):
  - never read outside the input span;
  - no type punning on packet memory;
  - compare sequence numbers only wrap-safely;
  - no wall-clock reads inside the stack;
  - every checksum variant agrees with the reference;
  - every TCP change cites its RFC section and passes the 200-network simulation.

## Guardrails

[`.claude/settings.json`](../.claude/settings.json) pre-approves builds and tests in the container, and denies:

- `git push`;
- `sudo`;
- configuring interfaces on the host;
- privileged containers, except through `scripts/integration.sh`.

The TAP device only ever exists inside that throwaway container. A hook runs clang-format on every edited
file.

## Repeatable workflows

- **Skills:**
  - [`add-tcp-behaviour`](../.claude/skills/add-tcp-behaviour/SKILL.md) goes from the RFC section to a
    scripted test, the simulation and fuzzing;
  - [`run-integration`](../.claude/skills/run-integration/SKILL.md) runs the interop test against Linux and
    reads its failures.
- **A reviewer subagent**, [`rfc-reviewer`](../.claude/agents/rfc-reviewer.md), checks TCP diffs against
  RFC 9293, 5681, 6298, 6582 and 7323.

## Verification instead of trust

Every step had to pass the following under GCC, Clang, and ASan with UBSan:

- unit tests and scripted packet exchanges;
- a deterministic simulation across 200 random lossy networks;
- the fuzzers (UB aborts);
- interop with Linux over TAP, with SHA-256-verified transfers.

Numbers in the README come only from the saved script output in [`docs/results/`](results).

## What the checks caught

| Caught by | Issue | Fix |
|-----------|-------|-----|
| 200-network simulation, then tcpdump on a replayed seed | **An ACK war.** After both ends timed out and rewound for go-back-N, their pure ACKs carried the rewound sequence number. Each end dropped the other's ACKs unprocessed as old duplicates, until one gave up and reset. | Pure ACKs and RSTs carry `snd_max`, BSD's rule. |
| Zero-window test | A window update that acknowledged nothing new cancelled the probe timer but never resumed sending: a silent stall. | Resume sending when the window opens. |
| `fuzz_stack` under UBSan | `memcpy` from an empty span's null pointer in the send buffer: undefined behaviour even for zero bytes. | Return early on empty input; regression test. |
| Checksum property test | The *reference* implementation overflowed its 32-bit sum past 128 KiB. | Sum into 64 bits. |
| Benchmarks and disassembly | A NEON loop ran 7× slower than the same algorithm in a standalone program. GCC had fused two loads into one `LDP`. | Index from two bases so GCC emits two `LDR`s: 7 → 50–66 GB/s. |

## What I own

- **The problem, the constraints, and what is out of scope:** SACK, timestamps and IPv6, stated in the spec.
- **Whether a result means what it seems to.** The NEON slowdown first looked like a dependency-chain problem
  and turned out to be the load instruction.
- **The review.** I check the code against the spec and the RFCs, and what I can explain line by line is the
  measure of what I present.

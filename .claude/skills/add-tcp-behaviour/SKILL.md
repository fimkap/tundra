---
name: add-tcp-behaviour
description: Checklist for adding or changing a TCP behaviour in tundra (a new option, a timer, a congestion-control change, a state-machine fix), from the RFC to the tests. Use for any change under src/tcp.cpp or include/tundra/tcp.hpp.
---

# Adding a TCP behaviour

1. **Find the rule.** Quote the governing RFC section (9293, 5681, 6298, 6582, 7323, 5961, 6528) in the
   code comment next to the change. If the RFC leaves a choice, write down which one and why in
   `docs/design.md`.
2. **Scripted test first.** In `tests/tcp_test.cpp` (`Scripted` fixture): inject the exact segments,
   assert the exact segments the stack emits (flags, seq, ack, window, options). Time moves only through
   `ManualClock`; never sleep.
3. **Implement.** Compare sequence numbers only with `seq_lt`/`seq_le`/... on the wire, or on the 64-bit
   internal offsets. Never `<` on raw 32-bit values.
4. **Simulation.** Run `ctest --preset debug`: the 200-network property test must still pass. If a seed
   fails, replay it with `SIM_SEED=n SIM_PCAP=/src/build/seed.pcap` and read it with
   `tcpdump -nn -r /src/build/seed.pcap`.
5. **Sanitizers and fuzzing.** `ctest --preset asan`, then `scripts/fuzz.sh 60`. Extend `fuzz_stack.cpp`
   if the change adds an API call or an option the fuzzer can't reach.
6. **Interop.** `scripts/integration.sh`: Linux must still agree.
7. **Review.** Run the `rfc-reviewer` subagent on the diff before committing.

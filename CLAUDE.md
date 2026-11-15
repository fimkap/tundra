@AGENTS.md

## Claude Code specifics

- `.claude/settings.json` pre-approves `scripts/dev.sh` builds and tests and read-only git; it denies
  `git push`, `sudo`, `ip link`/`ip addr` on the host, and `docker run --privileged` except through
  `scripts/integration.sh`.
- A `PostToolUse` hook runs `clang-format` on edited C++ files when clang-format is installed (inside the
  container it always is).
- The `rfc-reviewer` subagent (`.claude/agents/`) checks TCP changes against RFC 9293, 5681, 6298 and 6582
  before they are committed.
- Skills: `add-tcp-behaviour` (spec, RFC cite, scripted test, simulation, fuzz) and `run-integration`.

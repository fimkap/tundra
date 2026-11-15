# Fuzzing

- libFuzzer with ASan and UBSan (clang 19, -fno-sanitize-recover=all), both targets in parallel in the dev container
- run at 2026-11-15 22:22 UTC

| target | seconds | executions | coverage (edges) | features | corpus | result |
|---|---:|---:|---:|---:|---:|---|
| fuzz_parsers | 120 | 38577238 | 118 | 248 | 101 | clean |
| fuzz_stack | 120 | 598396 | 908 | 4653 | 688 | clean |

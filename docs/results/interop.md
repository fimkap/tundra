# tundra interop with Linux

- Linux 7.0.14-linuxkit, 4 CPUs, inside Docker; tundra on tap0 (10.0.0.2), Linux on the other side (10.0.0.1)
- loss is injected by tundra's device in both directions (--loss); added delay by tc netem: yes
- run at 2026-11-15 22:33 UTC

## Basics

| check | result |
|---|---|
| ping (3 packets) | 3 received, avg 0.182 ms |
| UDP echo | yes |
| TCP echo | yes |
| HTTP GET / | yes |
| 20 parallel 1 MiB downloads, SHA-256 verified | 20 of 20 |

## Bulk transfers

Each row downloads N bytes from tundra (tundra's TCP sends) and uploads them back (Linux's TCP sends);
both directions are verified with SHA-256.

| link | size | download MiB/s | upload MiB/s | download verified | upload verified |
|---|---:|---:|---:|---|---|
| clean | 64 MiB | 83.6 | 37.7 | yes | yes |
| 1% loss each way | 16 MiB | 5.6 | 13.2 | yes | yes |
| 1% loss each way, +5 ms delay | 8 MiB | 1.1 | 1.7 | yes | yes |
| 5% loss each way, +5 ms delay | 4 MiB | 0.2 | 0.4 | yes | yes |

All checks passed.

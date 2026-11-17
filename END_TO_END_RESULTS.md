# Sprint 3 results: end-to-end latency and throughput

End-to-end latency and throughput of authenticated requests sent through the Sprint 2 stack, http.client or Chromium → nginx → waitress → application, for all six configurations: RS256, ES256, EdDSA, ML-DSA-44, SLH-DSA-SHA2-128s, and SLH-DSA-SHA2-128f (stack and command: [TRANSPORT.md](TRANSPORT.md#the-load-command); task: [PROGRESS.md](PROGRESS.md#s3-01--measure-end-to-end-latency-and-throughput)). This document covers S3-01. Every request's time is split into token transfer, verification, and other server handling, and each configuration's difference from ES256 is split into the part that comes from token size and the part that comes from verification.

Every number below comes from one run on the team's Mac (Apple M5 Pro, 18 cores, macOS 26.5.1, arm64, 16 KiB memory pages; Python 3.15.2, Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2 with its default 4 threads), recorded on November 17, 2026 (UTC) at commit `2e5dee3`:

| Machine | Run | Files |
| --- | --- | --- |
| Apple M5 Pro (macOS) | [`20261117T004351Z-macos`](results/load/20261117T004351Z-macos/) | [load.json](results/load/20261117T004351Z-macos/load.json), [raw.csv.gz](results/load/20261117T004351Z-macos/raw.csv.gz), [logs](results/load/20261117T004351Z-macos/logs/), [nginx.conf](results/load/20261117T004351Z-macos/nginx.conf) |

`load.json` has the settings, the workload, the environment, every cell's counts and latency components, the comparisons with ES256, and the network model. `raw.csv.gz` has all 335,277 measured requests with their timings in nanoseconds, and every summary here can be recomputed from it. The logs are gzip-compressed (`gzip -dc`); every verified request's nonce is in `proxy-access.log.gz` and `app.log.gz`, and no log, `load.json`, or `raw.csv.gz` contains a token.

## Workload

- **Request mix:** 100% `GET /api/token/verify?timing=1&nonce=<32 hex digits>`, an authenticated request whose only server work is verifying the token, because verification runs on every authenticated request. Signing is not part of the workload; its cost is Sprint 1's in-process measurement in [RESULTS.md](RESULTS.md).
- **Transport:** the token in an `Authorization: Bearer` header, the only transport that can carry all six configurations. nginx's request header buffers were raised with `--header-buffers 32k` (`large_client_header_buffers 4 32k`), the smallest power-of-two size that fits SLH-DSA-SHA2-128f's 22,946-byte `Authorization` line; at the default 8k, nginx rejects both SLH-DSA tokens with 400 (see [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md#bearer-header-boundaries)).
- **Clients**, both on the same Mac as the stack, reaching nginx over loopback at 127.0.0.1:
  - **http.client (direct):** one thread per worker in the load process, each with its own persistent HTTP/1.1 connection to nginx, timed with `time.perf_counter_ns()`.
  - **Chromium (browser):** headless Chromium (Playwright, channel `chromium`) running `fetch()` loops in the test page it loaded through nginx, with a new browser context per cell, timed with `performance.now()`.
- **Loop and concurrency:** closed loop, each worker sending its next request only after reading the previous response body, with 1 worker (unloaded latency) and 4 workers (waitress's thread count) per cell.
- **Duration and warm-up:** 1 second of unrecorded warm-up, then 2 seconds measured, per cell. The default is 5 seconds; it was shortened to 2 because a 5-second run writes a `raw.csv.gz` larger than the 10 MiB limit for a committed file (this run's is 6.0 MB).
- **Cells:** for each client, concurrency, and configuration, a token cell with the configuration's own token (minimal claims, [fixtures/claims.json](fixtures/claims.json)), and, for every configuration except ES256, a size-control cell with ES256's token padded with the `pad` claim to the configuration's size. Each cell got its token once, through nginx, before its warm-up. 44 cells in all.
- **nginx to waitress:** `--upstream-keepalive 64`, which is not a default: nginx keeps up to 64 idle connections to waitress instead of opening one per request. Without it, a sustained load runs out of macOS's 16,384 ephemeral ports within seconds, because each closed connection holds a port in TIME_WAIT for 30 seconds (see [TRANSPORT.md](TRANSPORT.md#configuration-that-is-not-a-default)). It is recorded in `load.json` as `settings.upstream_keepalive` (and described in `workload.client_location.network`), so `--settings` reuses it, and marked `Not a default` in `nginx.conf`.
- **Machine state:** the other S3-01 candidates were not running during this run (their processes were sampled every 5 seconds, and none appeared); the usual desktop applications were open, and the 1-minute load average was 2.7–4.2 on 18 cores. An earlier attempt the same evening overlapped another candidate's test run: the shared ephemeral ports ran out, its requests failed with 502 and `Can't assign requested address`, and it was discarded. The team will rerun `make load` on an otherwise idle Mac and replace these numbers.

The command used:

```bash
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir results/load/20261117T004351Z-macos
```

Its summary output, one line per client, concurrency, and configuration: the token size, the median and p95 latency, the throughput, and the difference of the mean latency from ES256 split into token size and verification, followed by the size control's split:

```text
direct  c=1   RS256                464 B  median   0.170 ms  p95   0.182 ms    5,835.7 req/s  vs ES256 -0.012 ms = size +0.006 + verification -0.018  (control: size +0.011 + verification -0.023)
direct  c=1   ES256                208 B  median   0.182 ms  p95   0.198 ms    5,445.3 req/s  vs ES256 +0.000 ms = size +0.000 + verification +0.000
direct  c=1   EdDSA                208 B  median   0.175 ms  p95   0.188 ms    5,661.9 req/s  vs ES256 -0.007 ms = size -0.007 + verification -0.000  (control: size -0.007 + verification -0.000)
direct  c=1   ML-DSA-44          3,355 B  median   0.207 ms  p95   0.226 ms    4,774.6 req/s  vs ES256 +0.026 ms = size +0.021 + verification +0.005  (control: size +0.088 + verification -0.062)
direct  c=1   SLH-DSA-SHA2-128s 10,613 B  median   0.387 ms  p95   0.406 ms    2,562.0 req/s  vs ES256 +0.206 ms = size +0.138 + verification +0.069  (control: size +0.325 + verification -0.118)
direct  c=1   SLH-DSA-SHA2-128f 22,922 B  median   0.685 ms  p95   0.717 ms    1,448.4 req/s  vs ES256 +0.506 ms = size +0.241 + verification +0.265  (control: size +0.629 + verification -0.123)
direct  c=4   RS256                464 B  median   0.501 ms  p95   0.766 ms    7,669.8 req/s  vs ES256 +0.024 ms = size +0.018 + verification +0.005  (control: size +0.032 + verification -0.008)
direct  c=4   ES256                208 B  median   0.478 ms  p95   0.742 ms    8,035.0 req/s  vs ES256 +0.000 ms = size +0.000 + verification +0.000
direct  c=4   EdDSA                208 B  median   0.462 ms  p95   0.718 ms    8,284.6 req/s  vs ES256 -0.015 ms = size -0.018 + verification +0.003  (control: size +0.001 + verification -0.016)
direct  c=4   ML-DSA-44          3,355 B  median   0.465 ms  p95   0.708 ms    8,261.6 req/s  vs ES256 -0.014 ms = size -0.019 + verification +0.006  (control: size +0.287 + verification -0.301)
direct  c=4   SLH-DSA-SHA2-128s 10,613 B  median   1.008 ms  p95   1.482 ms    3,886.5 req/s  vs ES256 +0.531 ms = size +0.539 + verification -0.008  (control: size +0.940 + verification -0.409)
direct  c=4   SLH-DSA-SHA2-128f 22,922 B  median   2.012 ms  p95   2.642 ms    1,967.5 req/s  vs ES256 +1.533 ms = size +1.346 + verification +0.187  (control: size +1.974 + verification -0.441)
browser c=1   RS256                464 B  median   0.400 ms  p95   0.500 ms    2,636.7 req/s  vs ES256 -0.002 ms = size +0.017 + verification -0.019  (control: size +0.014 + verification -0.015)
browser c=1   ES256                208 B  median   0.400 ms  p95   0.500 ms    2,625.4 req/s  vs ES256 +0.000 ms = size +0.000 + verification +0.000
browser c=1   EdDSA                208 B  median   0.400 ms  p95   0.500 ms    2,592.7 req/s  vs ES256 +0.005 ms = size +0.005 + verification -0.001  (control: size +0.009 + verification -0.004)
browser c=1   ML-DSA-44          3,355 B  median   0.400 ms  p95   0.500 ms    2,226.9 req/s  vs ES256 +0.068 ms = size +0.064 + verification +0.004  (control: size +0.135 + verification -0.067)
browser c=1   SLH-DSA-SHA2-128s 10,613 B  median   0.600 ms  p95   0.700 ms    1,674.4 req/s  vs ES256 +0.216 ms = size +0.147 + verification +0.069  (control: size +0.323 + verification -0.107)
browser c=1   SLH-DSA-SHA2-128f 22,922 B  median   0.900 ms  p95   1.000 ms    1,137.5 req/s  vs ES256 +0.498 ms = size +0.244 + verification +0.254  (control: size +0.645 + verification -0.148)
browser c=4   RS256                464 B  median   0.800 ms  p95   1.200 ms    4,517.6 req/s  vs ES256 -0.029 ms = size +0.000 + verification -0.029  (control: size +0.016 + verification -0.046)
browser c=4   ES256                208 B  median   0.800 ms  p95   1.200 ms    4,374.4 req/s  vs ES256 +0.000 ms = size +0.000 + verification +0.000
browser c=4   EdDSA                208 B  median   0.800 ms  p95   1.100 ms    4,632.8 req/s  vs ES256 -0.051 ms = size -0.031 + verification -0.020  (control: size -0.045 + verification -0.006)
browser c=4   ML-DSA-44          3,355 B  median   0.900 ms  p95   1.200 ms    4,304.2 req/s  vs ES256 +0.015 ms = size +0.019 + verification -0.004  (control: size +0.191 + verification -0.176)
browser c=4   SLH-DSA-SHA2-128s 10,613 B  median   1.200 ms  p95   1.900 ms    2,953.3 req/s  vs ES256 +0.440 ms = size +0.467 + verification -0.027  (control: size +0.861 + verification -0.421)
browser c=4   SLH-DSA-SHA2-128f 22,922 B  median   2.300 ms  p95   3.400 ms    1,735.5 req/s  vs ES256 +1.388 ms = size +1.216 + verification +0.172  (control: size +1.998 + verification -0.610)
Saved the results to results/load/20261117T004351Z-macos
```

## Latency and throughput

Every measured request verified: 335,277 requests, no failures, every one with status 200. Latency is the client-measured time from sending a request to reading its whole response body, in milliseconds; p95 uses the nearest-rank method, as in Sprint 1. Throughput is verified requests per second of the measured phase, for the whole closed loop. Chromium's timer is coarsened to about 0.1 ms, so its medians and p95 values are multiples of 0.1 ms; its means, used below, are not.

**http.client (direct), concurrency 1**

| Configuration | Token bytes | Median (ms) | p95 (ms) | Mean (ms) | Throughput (req/s) | Verified requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | 0.170 | 0.182 | 0.171 | 5,836 | 11,672 |
| ES256 | 208 | 0.182 | 0.198 | 0.183 | 5,445 | 10,891 |
| EdDSA | 208 | 0.175 | 0.188 | 0.176 | 5,662 | 11,324 |
| ML-DSA-44 | 3,355 | 0.207 | 0.226 | 0.209 | 4,775 | 9,550 |
| SLH-DSA-SHA2-128s | 10,613 | 0.387 | 0.406 | 0.389 | 2,562 | 5,125 |
| SLH-DSA-SHA2-128f | 22,922 | 0.685 | 0.717 | 0.689 | 1,448 | 2,897 |

**http.client (direct), concurrency 4**

| Configuration | Token bytes | Median (ms) | p95 (ms) | Mean (ms) | Throughput (req/s) | Verified requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | 0.501 | 0.766 | 0.520 | 7,670 | 15,342 |
| ES256 | 208 | 0.478 | 0.742 | 0.497 | 8,035 | 16,073 |
| EdDSA | 208 | 0.462 | 0.718 | 0.482 | 8,285 | 16,572 |
| ML-DSA-44 | 3,355 | 0.465 | 0.708 | 0.483 | 8,262 | 16,526 |
| SLH-DSA-SHA2-128s | 10,613 | 1.008 | 1.482 | 1.028 | 3,887 | 7,777 |
| SLH-DSA-SHA2-128f | 22,922 | 2.012 | 2.642 | 2.030 | 1,967 | 3,938 |

**Chromium (browser), concurrency 1**

| Configuration | Token bytes | Median (ms) | p95 (ms) | Mean (ms) | Throughput (req/s) | Verified requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | 0.400 | 0.500 | 0.379 | 2,637 | 5,274 |
| ES256 | 208 | 0.400 | 0.500 | 0.381 | 2,625 | 5,251 |
| EdDSA | 208 | 0.400 | 0.500 | 0.385 | 2,593 | 5,186 |
| ML-DSA-44 | 3,355 | 0.400 | 0.500 | 0.449 | 2,227 | 4,454 |
| SLH-DSA-SHA2-128s | 10,613 | 0.600 | 0.700 | 0.597 | 1,674 | 3,349 |
| SLH-DSA-SHA2-128f | 22,922 | 0.900 | 1.000 | 0.879 | 1,138 | 2,276 |

**Chromium (browser), concurrency 4**

| Configuration | Token bytes | Median (ms) | p95 (ms) | Mean (ms) | Throughput (req/s) | Verified requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | 0.800 | 1.200 | 0.885 | 4,518 | 9,037 |
| ES256 | 208 | 0.800 | 1.200 | 0.914 | 4,374 | 8,855 |
| EdDSA | 208 | 0.800 | 1.100 | 0.863 | 4,633 | 9,268 |
| ML-DSA-44 | 3,355 | 0.900 | 1.200 | 0.929 | 4,304 | 8,611 |
| SLH-DSA-SHA2-128s | 10,613 | 1.200 | 1.900 | 1.354 | 2,953 | 5,909 |
| SLH-DSA-SHA2-128f | 22,922 | 2.300 | 3.400 | 2.302 | 1,735 | 3,473 |

- **Classical and ML-DSA-44:** RS256, ES256, EdDSA, and ML-DSA-44 are within about 0.07 ms of each other in every cell. ML-DSA-44 served 12% fewer requests per second than ES256 from http.client at concurrency 1 and 15% fewer from Chromium. At concurrency 4, all four are within 6% of ES256's throughput in both directions, which is the run's noise level: EdDSA, whose token is the same size as ES256's, differs by up to 5.9%.
- **SLH-DSA:** SLH-DSA-SHA2-128s served 52–53% fewer requests per second than ES256 from http.client and 33–36% fewer from Chromium; SLH-DSA-SHA2-128f served 73–76% and 57–60% fewer. Its median latency at concurrency 1 is 3.8× ES256's from http.client (0.685 against 0.182 ms) and 2.3× from Chromium (0.9 against 0.4 ms).
- **Clients:** Chromium adds about 0.2 ms per request over http.client at concurrency 1 for every configuration, so the same token differences are a smaller share of its latency.

## Token size versus verification

The application reports, with `timing=1`, how long the adapter's `verify_token` call took (`verify_ns`) and how long the whole verify handler took (`handler_ns`). Each verified request then splits into three components: **verification** (`verify_ns`), **other handling** (`handler_ns` - `verify_ns`: reading headers, choosing the key, and building the response), and **transfer** (the client's total - `handler_ns`: the client, the token's bytes through both connections, nginx, and waitress). The difference of each configuration's mean from ES256's token cell of the same client and concurrency then splits into **token size** (transfer + other handling, which is the total minus verification) and **verification**. Means are used because they add up exactly; the medians are in the tables above. All values are in milliseconds.

**http.client (direct), concurrency 1**

| Configuration | Token bytes | Total | Token size | Verification | Transfer | Other handling | Control: token size | Control: verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | -0.012 | +0.006 | -0.018 | +0.005 | +0.000 | +0.011 | -0.023 |
| ES256 | 208 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| EdDSA | 208 | -0.007 | -0.007 | -0.000 | -0.006 | -0.001 | -0.007 | -0.000 |
| ML-DSA-44 | 3,355 | +0.026 | +0.021 | +0.005 | +0.020 | +0.001 | +0.088 | -0.062 |
| SLH-DSA-SHA2-128s | 10,613 | +0.206 | +0.138 | +0.069 | +0.136 | +0.002 | +0.325 | -0.118 |
| SLH-DSA-SHA2-128f | 22,922 | +0.506 | +0.241 | +0.265 | +0.235 | +0.006 | +0.629 | -0.123 |

**http.client (direct), concurrency 4**

| Configuration | Token bytes | Total | Token size | Verification | Transfer | Other handling | Control: token size | Control: verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | +0.024 | +0.018 | +0.005 | +0.018 | +0.000 | +0.032 | -0.008 |
| ES256 | 208 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| EdDSA | 208 | -0.015 | -0.018 | +0.003 | -0.018 | -0.000 | +0.001 | -0.016 |
| ML-DSA-44 | 3,355 | -0.014 | -0.019 | +0.006 | -0.020 | +0.001 | +0.287 | -0.301 |
| SLH-DSA-SHA2-128s | 10,613 | +0.531 | +0.539 | -0.008 | +0.536 | +0.003 | +0.940 | -0.409 |
| SLH-DSA-SHA2-128f | 22,922 | +1.533 | +1.346 | +0.187 | +1.339 | +0.007 | +1.974 | -0.441 |

**Chromium (browser), concurrency 1**

| Configuration | Token bytes | Total | Token size | Verification | Transfer | Other handling | Control: token size | Control: verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | -0.002 | +0.017 | -0.019 | +0.017 | +0.000 | +0.014 | -0.015 |
| ES256 | 208 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| EdDSA | 208 | +0.005 | +0.005 | -0.001 | +0.005 | +0.000 | +0.009 | -0.004 |
| ML-DSA-44 | 3,355 | +0.068 | +0.064 | +0.004 | +0.063 | +0.001 | +0.135 | -0.067 |
| SLH-DSA-SHA2-128s | 10,613 | +0.216 | +0.147 | +0.069 | +0.142 | +0.006 | +0.323 | -0.107 |
| SLH-DSA-SHA2-128f | 22,922 | +0.498 | +0.244 | +0.254 | +0.235 | +0.009 | +0.645 | -0.148 |

**Chromium (browser), concurrency 4**

| Configuration | Token bytes | Total | Token size | Verification | Transfer | Other handling | Control: token size | Control: verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | -0.029 | +0.000 | -0.029 | +0.002 | -0.001 | +0.016 | -0.046 |
| ES256 | 208 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| EdDSA | 208 | -0.051 | -0.031 | -0.020 | -0.030 | -0.001 | -0.045 | -0.006 |
| ML-DSA-44 | 3,355 | +0.015 | +0.019 | -0.004 | +0.017 | +0.001 | +0.191 | -0.176 |
| SLH-DSA-SHA2-128s | 10,613 | +0.440 | +0.467 | -0.027 | +0.467 | +0.001 | +0.861 | -0.421 |
| SLH-DSA-SHA2-128f | 22,922 | +1.388 | +1.216 | +0.172 | +1.212 | +0.004 | +1.998 | -0.610 |

At concurrency 1, which isolates each request:

- **SLH-DSA-SHA2-128f:** of its +0.506 ms over ES256 from http.client, +0.241 ms (48%) comes from token size and +0.265 ms (52%) from verification. From Chromium the split is the same: +0.244 and +0.254 ms of +0.498 ms.
- **SLH-DSA-SHA2-128s:** of +0.206 ms, +0.138 ms (67%) comes from token size and +0.069 ms from verification (Chromium: +0.147 and +0.069 ms).
- **ML-DSA-44:** of +0.026 ms, +0.021 ms comes from token size and +0.005 ms from verification (Chromium: +0.064 and +0.004 ms of +0.068 ms).
- **RS256 and EdDSA:** RS256's token is 256 bytes larger than ES256's but verifies 0.018 ms faster, so its total is slightly lower. EdDSA's token is the same size as ES256's, and every difference is within 0.007 ms, which shows the noise level of a difference at concurrency 1.
- **Verification agrees with Sprint 1:** the verification differences from ES256 (-0.018, +0.005, +0.069, and +0.265 ms for RS256, ML-DSA-44, SLH-DSA-SHA2-128s, and SLH-DSA-SHA2-128f) are within 0.02 ms of Sprint 1's raw verify differences on the same Mac (-0.021, +0.013, +0.070, and +0.246 ms in [RESULTS.md](RESULTS.md)), although `verify_token` also parses the token.

At concurrency 4, the token-size share grows: SLH-DSA-SHA2-128f's difference is +1.533 ms from http.client, +1.346 ms of it attributed to token size. waitress runs the application's 4 threads in one Python process, so a request also waits while the other workers' requests are read, parsed, and verified. That waiting happens outside its own handler and is counted in its transfer, so part of each configuration's verification cost appears there too. The concurrency 1 split is the clean one; the concurrency 4 split shows that under load a larger token mostly costs queueing behind larger requests.

**Size-control check.** Each size control sends ES256's token padded to the configuration's size. Its transfer component matches the configuration's to within 0.018 ms at concurrency 1 (for example 0.368 against 0.357 ms for SLH-DSA-SHA2-128f from http.client, and 0.457 against 0.457 ms for SLH-DSA-SHA2-128s from Chromium), which confirms that the transfer difference comes from the token's size and not from its algorithm. The control's own split ("Control" columns: control - ES256 as token size, configuration - control as verification) overstates the size effect, though, and gives negative verification differences, because a padded token is not just a larger ES256 token. Its payload is the large part, so `verify_token` spends longer decoding and parsing it (0.392 ms against 0.049 ms for ES256's own token, from http.client at concurrency 1), and the verify response echoes the `pad` claim, so the response body is 17,478 bytes instead of 449. The components of that cell show where the control's time goes:

| Cell (http.client, concurrency 1) | Token bytes | Response body bytes | Total | Transfer | Other handling | Verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ES256 token | 208 | 429 | 0.183 | 0.122 | 0.011 | 0.049 |
| ML-DSA-44 token | 3,355 | 436 | 0.209 | 0.143 | 0.012 | 0.054 |
| ML-DSA-44 size control | 3,355 | 2,799 | 0.271 | 0.155 | 0.018 | 0.098 |
| SLH-DSA-SHA2-128s token | 10,613 | 449 | 0.389 | 0.258 | 0.013 | 0.118 |
| SLH-DSA-SHA2-128s size control | 10,612 | 8,246 | 0.507 | 0.269 | 0.032 | 0.206 |
| SLH-DSA-SHA2-128f token | 22,922 | 449 | 0.689 | 0.357 | 0.017 | 0.315 |
| SLH-DSA-SHA2-128f size control | 22,922 | 17,478 | 0.812 | 0.368 | 0.052 | 0.392 |

So over loopback, the answer to "how much comes from size and how much from verification" is: for SLH-DSA-SHA2-128f about half each, for SLH-DSA-SHA2-128s about two thirds size, and for ML-DSA-44 almost all size, but the whole ML-DSA-44 difference is under 0.07 ms. On a real network the size part grows; see the next section.

## Modeled network cost

Loopback makes token transfer nearly free: the measured transfer differences above are only copying and parsing. The figures in this section are **calculated, not measured**. They model what each configuration's request would take to upload on a real link, using the bytes of the request header block the direct client sends (the request line, `Host`, `Accept-Encoding: identity`, the `Authorization` line, and every CRLF). The three uplink and round-trip profiles are illustrative values chosen by the team, not measurements of any network.

The model, from `network_model` in `load.json`, assumes:

- the request goes out on a new or idle TCP connection, whose slow start sends an initial window of 10 segments of 1,460 bytes (14,600 bytes, RFC 6928) in the first round trip and twice as much in each later one, so a request of up to 14,600 bytes takes one flight, up to 43,800 two, and up to 102,200 three;
- upload time = request bytes × 8 / uplink rate + one round trip per flight after the first;
- upload only: no response, server time, or packet loss;
- no TLS, TCP/IP, or HTTP/2 framing overhead;
- the direct client's request; a browser's request carries several hundred bytes more of other headers (Chromium's verify requests reached the application with 493 more header bytes than http.client's).

Each profile column is the modeled upload time of the configuration's request minus ES256's, in milliseconds. The last column is the measured verification difference from ES256 (http.client, concurrency 1).

| Configuration | Request bytes | Extra bytes over ES256 | 100 Mbit/s, 10 ms RTT | 10 Mbit/s, 50 ms RTT | 1 Mbit/s, 100 ms RTT | Measured verification difference |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 620 | 256 | +0.020 | +0.205 | +2.048 | -0.018 |
| ES256 | 364 | 0 | 0.000 | 0.000 | 0.000 | 0.000 |
| EdDSA | 364 | 0 | 0.000 | 0.000 | 0.000 | -0.000 |
| ML-DSA-44 | 3,511 | 3,147 | +0.252 | +2.518 | +25.176 | +0.005 |
| SLH-DSA-SHA2-128s | 10,769 | 10,405 | +0.832 | +8.324 | +83.240 | +0.069 |
| SLH-DSA-SHA2-128f | 23,078 | 22,714 | +11.817 | +68.171 | +281.712 | +0.265 |

On every profile, the modeled transfer difference is larger than the measured verification difference: by 12× for SLH-DSA-SHA2-128s and 45× for SLH-DSA-SHA2-128f on the fastest profile, and by three orders of magnitude or more on the slowest. SLH-DSA-SHA2-128f's 23,078-byte request no longer fits in the initial window, so it also costs a full extra round trip. ML-DSA-44's 3,147 extra bytes add 0.25–25 ms against 0.005 ms of extra verification. For these profiles, this answers transport question 4: transfer matters more than verification for every post-quantum configuration. On a connection whose congestion window has already grown, the extra round trip disappears, but the serialization time does not.

## Reproduce

From a clean checkout with the environment from [TRANSPORT.md](TRANSPORT.md#setup), and with no other load on the machine (ephemeral ports are shared by every process, so another heavy client can exhaust them during the run):

```bash
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir results/load/<YYYYMMDDTHHMMSSZ>-macos
# the same workload from this run's saved settings:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --settings results/load/20261117T004351Z-macos/load.json --output-dir results/load/<YYYYMMDDTHHMMSSZ>-macos
# or, with TRANSPORT_ENV set:
make load LOAD_DIR=results/load/<YYYYMMDDTHHMMSSZ>-macos
```

The run took about 2.5 minutes. `--output-dir` must not exist yet or be empty. `--settings` reuses every setting in `load.json` (configurations, transport, clients, claims, concurrency, duration, warm-up, reference, size controls, timeout, nginx buffers, and the upstream keepalive count). The tables in this document come from `results` and `comparisons` in `load.json`, and each cell's counts, medians, p95, and means can be recomputed from its rows in `raw.csv.gz` (`gzip -dc raw.csv.gz`). [TRANSPORT.md](TRANSPORT.md#the-load-command) describes every option, field, and column.

## Limitations

- **Loopback only.** Every measurement ran over loopback on one machine, so the measured transfer component has no real network bandwidth or round trips in it: it is copying and parsing in the client, nginx, and waitress. The network cost of a token is only calculated, in [Modeled network cost](#modeled-network-cost).
- **One machine, one run.** These numbers are from one run on the Mac. The WSL2 run has not been done yet. The run was not on an otherwise idle machine (desktop applications were open), and other S3-01 candidates ran on the same Mac before and after it, so numbers from different runs or candidates should not be compared. The team will rerun it on an idle Mac.
- **Shortened duration.** Each cell measured 2 seconds instead of the default 5, to keep `raw.csv.gz` under 10 MiB. Every cell still had at least 1,948 verified requests.
- **Not nginx's default upstream connections.** `--upstream-keepalive 64` was needed on macOS and removes nginx's per-request connection to waitress from every request's time, for every configuration alike. Without it, the absolute latencies would be higher, and a sustained run on macOS fails within seconds.
- **Raised header buffers.** The SLH-DSA tokens reach the application only with `--header-buffers 32k`; at nginx's default limits they are rejected (S2-05).
- **Coarse browser timer.** Chromium coarsens `performance.now()` to about 0.1 ms in a page that is not cross-origin isolated, so the browser's medians and p95 values are multiples of 0.1 ms and single requests can show a transfer component below zero. Its means and differences of means average over thousands of requests.
- **Size controls are not pure size.** A padded control has a large payload, which makes `verify_token` and the response larger (the response echoes the `pad` claim; `bytes.response_body` in `load.json` records it), so the control check confirms the transfer component but overstates the size effect of its own total.
- **Concurrency 4 mixes in queueing.** At concurrency 4, time spent waiting for other requests in waitress's single Python process is counted in transfer, so the token-size share there includes queueing behind larger requests.
- **One request type, one claims fixture, HTTP/1.1 without TLS.** Only `GET /api/token/verify` with the minimal claims fixture and a Bearer header was measured, over plain HTTP/1.1; cookies, larger claim sets, HTTPS, and HTTP/2 are not covered here (S3-02 and S3-04).

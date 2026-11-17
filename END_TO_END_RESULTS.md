# Sprint 3 results: end-to-end latency and throughput

End-to-end latency and throughput of authenticated requests sent through the Sprint 2 stack, http.client or Chromium → nginx → waitress → application, for all six configurations: RS256, ES256, EdDSA, ML-DSA-44, SLH-DSA-SHA2-128s, and SLH-DSA-SHA2-128f (stack and command: [TRANSPORT.md](TRANSPORT.md#the-load-command); task: [PROGRESS.md](PROGRESS.md#s3-01--measure-end-to-end-latency-and-throughput)). This document covers S3-01. Every request's time is split into token transfer, verification, and other server handling, and each configuration's difference from ES256 is split into the part that comes from token size and the part that comes from verification.

Every number below comes from one run on the team's Mac (Apple M5 Pro, 18 cores, macOS 26.5.1, arm64, 16 KiB memory pages; Python 3.15.2, Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2 with its default 4 threads), recorded on November 17, 2026 (UTC) at commit `15bcb7d`:

| Machine | Run | Files |
| --- | --- | --- |
| Apple M5 Pro (macOS) | [`20261117T035444Z-macos`](results/load/20261117T035444Z-macos/) | [load.json](results/load/20261117T035444Z-macos/load.json), [raw.csv.gz](results/load/20261117T035444Z-macos/raw.csv.gz), [logs](results/load/20261117T035444Z-macos/logs/), [nginx.conf](results/load/20261117T035444Z-macos/nginx.conf) |

`load.json` has the settings, the workload, the environment, every cell's counts and latency components, the comparisons with ES256, and the network model. `raw.csv.gz` has all 315,293 measured requests with their timings in nanoseconds, and every summary here can be recomputed from it. The logs are gzip-compressed (`gzip -dc`); every verified request's nonce is in `proxy-access.log.gz` and `app.log.gz`, and no log, `load.json`, or `raw.csv.gz` contains a token.

## Workload

- **Request mix:** 100% `GET /api/token/verify?timing=1&nonce=<32 hex digits>`, an authenticated request whose only server work is verifying the token, because verification runs on every authenticated request. Signing is not part of the workload; its cost is Sprint 1's in-process measurement in [RESULTS.md](RESULTS.md).
- **Transport:** the token in an `Authorization: Bearer` header, the only transport that can carry all six configurations. nginx's request header buffers were raised with `--header-buffers 32k` (`large_client_header_buffers 4 32k`), the smallest power-of-two size that fits SLH-DSA-SHA2-128f's 22,946-byte `Authorization` line; at the default 8k, nginx rejects both SLH-DSA tokens with 400 (see [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md#bearer-header-boundaries)).
- **Clients**, both on the same Mac as the stack, reaching nginx over loopback at 127.0.0.1:
  - **http.client (direct):** one thread per worker in the load process, each with its own persistent HTTP/1.1 connection to nginx, timed with `time.perf_counter_ns()`.
  - **Chromium (browser):** headless Chromium (Playwright, channel `chromium`) running `fetch()` loops in the test page it loaded through nginx, with a new browser context per cell, timed with `performance.now()`.
- **Loop and concurrency:** closed loop, each worker sending its next request only after reading the previous response body, with 1 worker (unloaded latency) and 4 workers (waitress's thread count) per cell.
- **Duration and warm-up:** 1 second of unrecorded warm-up, then 2 seconds measured, per cell. The default is 5 seconds; it was shortened to 2 because a 5-second run writes a `raw.csv.gz` larger than the 10 MiB limit for a committed file (this run's is 5.7 MB).
- **Cells:** for each client, concurrency, and configuration, a token cell with the configuration's own token (minimal claims, [fixtures/claims.json](fixtures/claims.json)), and, for every configuration except ES256, a size-control cell with ES256's token padded with the `pad` claim to the configuration's size. Each cell got its token once, through nginx, before its warm-up. 44 cells in all.
- **nginx to waitress:** `--upstream-keepalive 64`, which is not a default: nginx keeps up to 64 idle connections to waitress instead of opening one per request. Without it, a sustained load runs out of macOS's 16,384 ephemeral ports within seconds, because each closed connection holds a port in TIME_WAIT for 30 seconds (see [TRANSPORT.md](TRANSPORT.md#configuration-that-is-not-a-default)). It is recorded in `load.json` as `settings.upstream_keepalive` (and described in `workload.client_location.network`), so `--settings` reuses it, and marked `Not a default` in `nginx.conf`.
- **Machine state:** nothing else from the project was running (no S3-01 candidate, test suite, or other load run), and 6 sockets were in TIME_WAIT when the run started. Which desktop applications were open was not recorded. This run replaces a provisional one recorded earlier the same evening, while the S3-01 candidates were still being tested on the same Mac.

The command used, run by `make load` with `TRANSPORT_ENV` set:

```bash
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir "results/load/20261117T035444Z-macos"
```

Its summary output, one line per client, concurrency, and configuration: the token size, the median and p95 latency, the throughput, and the difference of the mean latency from ES256 split into token size and verification, followed by the size control's split:

```text
direct  c=1   RS256                464 B  median   0.178 ms  p95   0.202 ms    5,469.1 req/s  vs ES256 -0.013 ms = size +0.005 + verification -0.018  (control: size +0.016 + verification -0.029)
direct  c=1   ES256                208 B  median   0.192 ms  p95   0.215 ms    5,111.4 req/s  vs ES256 +0.000 ms = size +0.000 + verification +0.000
direct  c=1   EdDSA                208 B  median   0.192 ms  p95   0.216 ms    5,107.9 req/s  vs ES256 +0.000 ms = size +0.000 + verification -0.000  (control: size +0.010 + verification -0.010)
direct  c=1   ML-DSA-44          3,355 B  median   0.221 ms  p95   0.246 ms    4,453.3 req/s  vs ES256 +0.029 ms = size +0.025 + verification +0.004  (control: size +0.084 + verification -0.055)
direct  c=1   SLH-DSA-SHA2-128s 10,613 B  median   0.419 ms  p95   0.435 ms    2,377.5 req/s  vs ES256 +0.225 ms = size +0.153 + verification +0.072  (control: size +0.336 + verification -0.111)
direct  c=1   SLH-DSA-SHA2-128f 22,922 B  median   0.684 ms  p95   0.738 ms    1,445.5 req/s  vs ES256 +0.496 ms = size +0.233 + verification +0.263  (control: size +0.635 + verification -0.139)
direct  c=4   RS256                464 B  median   0.532 ms  p95   0.867 ms    7,116.4 req/s  vs ES256 +0.022 ms = size +0.020 + verification +0.002  (control: size +0.041 + verification -0.020)
direct  c=4   ES256                208 B  median   0.517 ms  p95   0.805 ms    7,400.6 req/s  vs ES256 +0.000 ms = size +0.000 + verification +0.000
direct  c=4   EdDSA                208 B  median   0.489 ms  p95   0.756 ms    7,843.1 req/s  vs ES256 -0.031 ms = size -0.031 + verification +0.001  (control: size -0.015 + verification -0.015)
direct  c=4   ML-DSA-44          3,355 B  median   0.487 ms  p95   0.770 ms    7,754.1 req/s  vs ES256 -0.025 ms = size -0.026 + verification +0.001  (control: size +0.245 + verification -0.269)
direct  c=4   SLH-DSA-SHA2-128s 10,613 B  median   1.002 ms  p95   1.537 ms    3,865.1 req/s  vs ES256 +0.494 ms = size +0.508 + verification -0.013  (control: size +0.958 + verification -0.464)
direct  c=4   SLH-DSA-SHA2-128f 22,922 B  median   2.064 ms  p95   3.010 ms    1,904.8 req/s  vs ES256 +1.557 ms = size +1.370 + verification +0.188  (control: size +1.947 + verification -0.390)
browser c=1   RS256                464 B  median   0.400 ms  p95   0.500 ms    2,465.5 req/s  vs ES256 -0.021 ms = size -0.002 + verification -0.020  (control: size +0.017 + verification -0.038)
browser c=1   ES256                208 B  median   0.400 ms  p95   0.500 ms    2,341.9 req/s  vs ES256 +0.000 ms = size +0.000 + verification +0.000
browser c=1   EdDSA                208 B  median   0.400 ms  p95   0.600 ms    2,121.0 req/s  vs ES256 +0.044 ms = size +0.043 + verification +0.001  (control: size +0.006 + verification +0.038)
browser c=1   ML-DSA-44          3,355 B  median   0.500 ms  p95   0.600 ms    2,074.6 req/s  vs ES256 +0.055 ms = size +0.054 + verification +0.001  (control: size +0.152 + verification -0.097)
browser c=1   SLH-DSA-SHA2-128s 10,613 B  median   0.600 ms  p95   0.800 ms    1,539.0 req/s  vs ES256 +0.222 ms = size +0.152 + verification +0.071  (control: size +0.375 + verification -0.153)
browser c=1   SLH-DSA-SHA2-128f 22,922 B  median   0.900 ms  p95   1.000 ms    1,080.8 req/s  vs ES256 +0.498 ms = size +0.234 + verification +0.264  (control: size +0.702 + verification -0.204)
browser c=4   RS256                464 B  median   0.800 ms  p95   1.300 ms    4,324.9 req/s  vs ES256 -0.084 ms = size -0.048 + verification -0.036  (control: size -0.098 + verification +0.015)
browser c=4   ES256                208 B  median   0.900 ms  p95   1.500 ms    3,965.8 req/s  vs ES256 +0.000 ms = size +0.000 + verification +0.000
browser c=4   EdDSA                208 B  median   0.800 ms  p95   1.300 ms    4,450.4 req/s  vs ES256 -0.110 ms = size -0.090 + verification -0.020  (control: size -0.112 + verification +0.003)
browser c=4   ML-DSA-44          3,355 B  median   0.800 ms  p95   1.100 ms    4,517.1 req/s  vs ES256 -0.123 ms = size -0.097 + verification -0.026  (control: size +0.187 + verification -0.310)
browser c=4   SLH-DSA-SHA2-128s 10,613 B  median   1.300 ms  p95   2.000 ms    2,877.6 req/s  vs ES256 +0.381 ms = size +0.414 + verification -0.033  (control: size +0.799 + verification -0.418)
browser c=4   SLH-DSA-SHA2-128f 22,922 B  median   2.300 ms  p95   3.500 ms    1,699.5 req/s  vs ES256 +1.343 ms = size +1.170 + verification +0.172  (control: size +1.935 + verification -0.592)
Saved the results to results/load/20261117T035444Z-macos
```

## Latency and throughput

Every measured request verified: 315,293 requests, no failures, every one with status 200. Latency is the client-measured time from sending a request to reading its whole response body, in milliseconds; p95 uses the nearest-rank method, as in Sprint 1. Throughput is verified requests per second of the measured phase, for the whole closed loop. Chromium's timer is coarsened to about 0.1 ms, so its medians and p95 values are multiples of 0.1 ms; its means, used below, are not.

**http.client (direct), concurrency 1**

| Configuration | Token bytes | Median (ms) | p95 (ms) | Mean (ms) | Throughput (req/s) | Verified requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | 0.178 | 0.202 | 0.182 | 5,469 | 10,939 |
| ES256 | 208 | 0.192 | 0.215 | 0.195 | 5,111 | 10,223 |
| EdDSA | 208 | 0.192 | 0.216 | 0.195 | 5,108 | 10,216 |
| ML-DSA-44 | 3,355 | 0.221 | 0.246 | 0.224 | 4,453 | 8,907 |
| SLH-DSA-SHA2-128s | 10,613 | 0.419 | 0.435 | 0.419 | 2,377 | 4,755 |
| SLH-DSA-SHA2-128f | 22,922 | 0.684 | 0.738 | 0.690 | 1,445 | 2,891 |

**http.client (direct), concurrency 4**

| Configuration | Token bytes | Median (ms) | p95 (ms) | Mean (ms) | Throughput (req/s) | Verified requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | 0.532 | 0.867 | 0.561 | 7,116 | 14,236 |
| ES256 | 208 | 0.517 | 0.805 | 0.539 | 7,401 | 14,804 |
| EdDSA | 208 | 0.489 | 0.756 | 0.509 | 7,843 | 15,688 |
| ML-DSA-44 | 3,355 | 0.487 | 0.770 | 0.515 | 7,754 | 15,514 |
| SLH-DSA-SHA2-128s | 10,613 | 1.002 | 1.537 | 1.034 | 3,865 | 7,734 |
| SLH-DSA-SHA2-128f | 22,922 | 2.064 | 3.010 | 2.097 | 1,905 | 3,813 |

**Chromium (browser), concurrency 1**

| Configuration | Token bytes | Median (ms) | p95 (ms) | Mean (ms) | Throughput (req/s) | Verified requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | 0.400 | 0.500 | 0.405 | 2,466 | 4,931 |
| ES256 | 208 | 0.400 | 0.500 | 0.427 | 2,342 | 4,684 |
| EdDSA | 208 | 0.400 | 0.600 | 0.471 | 2,121 | 4,244 |
| ML-DSA-44 | 3,355 | 0.500 | 0.600 | 0.482 | 2,075 | 4,150 |
| SLH-DSA-SHA2-128s | 10,613 | 0.600 | 0.800 | 0.649 | 1,539 | 3,078 |
| SLH-DSA-SHA2-128f | 22,922 | 0.900 | 1.000 | 0.925 | 1,081 | 2,162 |

**Chromium (browser), concurrency 4**

| Configuration | Token bytes | Median (ms) | p95 (ms) | Mean (ms) | Throughput (req/s) | Verified requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | 0.800 | 1.300 | 0.924 | 4,325 | 8,652 |
| ES256 | 208 | 0.900 | 1.500 | 1.008 | 3,966 | 7,934 |
| EdDSA | 208 | 0.800 | 1.300 | 0.898 | 4,450 | 8,903 |
| ML-DSA-44 | 3,355 | 0.800 | 1.100 | 0.885 | 4,517 | 9,037 |
| SLH-DSA-SHA2-128s | 10,613 | 1.300 | 2.000 | 1.389 | 2,878 | 5,757 |
| SLH-DSA-SHA2-128f | 22,922 | 2.300 | 3.500 | 2.351 | 1,700 | 3,399 |

- **Classical and ML-DSA-44:** RS256, ES256, EdDSA, and ML-DSA-44 have mean latencies within 0.06 ms of each other in every http.client cell and within 0.13 ms in every Chromium cell. From http.client at concurrency 1, where EdDSA and ES256 differ by only 0.1%, ML-DSA-44 served 12.9% fewer requests per second than ES256. The other cells are noisier: EdDSA, whose token is the same size as ES256's, served 9.4% fewer requests per second than ES256 from Chromium at concurrency 1, and 6.0% (http.client) and 12.2% (Chromium) more at concurrency 4. ML-DSA-44's 11.4% fewer from Chromium at concurrency 1, and 4.8% and 13.9% more at concurrency 4, are within that noise.
- **SLH-DSA:** SLH-DSA-SHA2-128s served 48–54% fewer requests per second than ES256 from http.client and 27–34% fewer from Chromium; SLH-DSA-SHA2-128f served 72–74% and 54–57% fewer. Its median latency at concurrency 1 is 3.6× ES256's from http.client (0.684 against 0.192 ms) and 2.25× from Chromium (0.9 against 0.4 ms).
- **Clients:** Chromium adds 0.22–0.28 ms per request over http.client at concurrency 1 for every configuration, so the same token differences are a smaller share of its latency.

## Token size versus verification

The application reports, with `timing=1`, how long the adapter's `verify_token` call took (`verify_ns`) and how long the whole verify handler took (`handler_ns`). Each verified request then splits into three components: **verification** (`verify_ns`), **other handling** (`handler_ns` - `verify_ns`: reading headers, choosing the key, and building the response), and **transfer** (the client's total - `handler_ns`: the client, the token's bytes through both connections, nginx, and waitress). The difference of each configuration's mean from ES256's token cell of the same client and concurrency then splits into **token size** (transfer + other handling, which is the total minus verification) and **verification**. Means are used because they add up exactly; the medians are in the tables above. All values are in milliseconds.

**http.client (direct), concurrency 1**

| Configuration | Token bytes | Total | Token size | Verification | Transfer | Other handling | Control: token size | Control: verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | -0.013 | +0.005 | -0.018 | +0.005 | +0.000 | +0.016 | -0.029 |
| ES256 | 208 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| EdDSA | 208 | +0.000 | +0.000 | -0.000 | +0.000 | +0.000 | +0.010 | -0.010 |
| ML-DSA-44 | 3,355 | +0.029 | +0.025 | +0.004 | +0.023 | +0.001 | +0.084 | -0.055 |
| SLH-DSA-SHA2-128s | 10,613 | +0.225 | +0.153 | +0.072 | +0.149 | +0.004 | +0.336 | -0.111 |
| SLH-DSA-SHA2-128f | 22,922 | +0.496 | +0.233 | +0.263 | +0.226 | +0.007 | +0.635 | -0.139 |

**http.client (direct), concurrency 4**

| Configuration | Token bytes | Total | Token size | Verification | Transfer | Other handling | Control: token size | Control: verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | +0.022 | +0.020 | +0.002 | +0.020 | +0.000 | +0.041 | -0.020 |
| ES256 | 208 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| EdDSA | 208 | -0.031 | -0.031 | +0.001 | -0.031 | -0.000 | -0.015 | -0.015 |
| ML-DSA-44 | 3,355 | -0.025 | -0.026 | +0.001 | -0.026 | +0.000 | +0.245 | -0.269 |
| SLH-DSA-SHA2-128s | 10,613 | +0.494 | +0.508 | -0.013 | +0.505 | +0.002 | +0.958 | -0.464 |
| SLH-DSA-SHA2-128f | 22,922 | +1.557 | +1.370 | +0.188 | +1.362 | +0.007 | +1.947 | -0.390 |

**Chromium (browser), concurrency 1**

| Configuration | Token bytes | Total | Token size | Verification | Transfer | Other handling | Control: token size | Control: verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | -0.021 | -0.002 | -0.020 | -0.002 | -0.000 | +0.017 | -0.038 |
| ES256 | 208 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| EdDSA | 208 | +0.044 | +0.043 | +0.001 | +0.042 | +0.001 | +0.006 | +0.038 |
| ML-DSA-44 | 3,355 | +0.055 | +0.054 | +0.001 | +0.053 | +0.001 | +0.152 | -0.097 |
| SLH-DSA-SHA2-128s | 10,613 | +0.222 | +0.152 | +0.071 | +0.146 | +0.005 | +0.375 | -0.153 |
| SLH-DSA-SHA2-128f | 22,922 | +0.498 | +0.234 | +0.264 | +0.227 | +0.007 | +0.702 | -0.204 |

**Chromium (browser), concurrency 4**

| Configuration | Token bytes | Total | Token size | Verification | Transfer | Other handling | Control: token size | Control: verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 464 | -0.084 | -0.048 | -0.036 | -0.046 | -0.002 | -0.098 | +0.015 |
| ES256 | 208 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| EdDSA | 208 | -0.110 | -0.090 | -0.020 | -0.088 | -0.002 | -0.112 | +0.003 |
| ML-DSA-44 | 3,355 | -0.123 | -0.097 | -0.026 | -0.096 | -0.001 | +0.187 | -0.310 |
| SLH-DSA-SHA2-128s | 10,613 | +0.381 | +0.414 | -0.033 | +0.415 | -0.001 | +0.799 | -0.418 |
| SLH-DSA-SHA2-128f | 22,922 | +1.343 | +1.170 | +0.172 | +1.167 | +0.003 | +1.935 | -0.592 |

At concurrency 1, which isolates each request:

- **SLH-DSA-SHA2-128f:** of its +0.496 ms over ES256 from http.client, +0.233 ms (47%) comes from token size and +0.263 ms (53%) from verification. From Chromium the split is the same: +0.234 and +0.264 ms of +0.498 ms.
- **SLH-DSA-SHA2-128s:** of +0.225 ms, +0.153 ms (68%) comes from token size and +0.072 ms from verification (Chromium: +0.152 and +0.071 ms).
- **ML-DSA-44:** of +0.029 ms, +0.025 ms comes from token size and +0.004 ms from verification (Chromium: +0.054 and +0.001 ms of +0.055 ms).
- **RS256 and EdDSA:** RS256's token is 256 bytes larger than ES256's but verifies 0.018 ms faster, so its total is slightly lower. EdDSA's token is the same size as ES256's. From http.client every EdDSA difference is under 0.001 ms, but from Chromium its total is +0.044 ms, nearly all of it in transfer, which shows the noise level of a Chromium difference at concurrency 1.
- **Verification agrees with Sprint 1:** the verification differences from ES256 (-0.018, +0.004, +0.072, and +0.263 ms for RS256, ML-DSA-44, SLH-DSA-SHA2-128s, and SLH-DSA-SHA2-128f) are within 0.02 ms of Sprint 1's raw verify differences on the same Mac (-0.021, +0.013, +0.070, and +0.246 ms in [RESULTS.md](RESULTS.md)), although `verify_token` also parses the token.

At concurrency 4, the token-size share grows: SLH-DSA-SHA2-128f's difference is +1.557 ms from http.client, +1.370 ms of it attributed to token size. waitress runs the application's 4 threads in one Python process, so a request also waits while the other workers' requests are read, parsed, and verified. That waiting happens outside its own handler and is counted in its transfer, so part of each configuration's verification cost appears there too. The concurrency 1 split is the clean one; the concurrency 4 split shows that under load a larger token mostly costs queueing behind larger requests.

**Size-control check.** Each size control sends ES256's token padded to the configuration's size. From http.client at concurrency 1, its transfer component matches the configuration's to within 0.011 ms (0.370 against 0.359 ms for SLH-DSA-SHA2-128f, and 0.281 against 0.281 ms for SLH-DSA-SHA2-128s), which confirms that the transfer difference comes from the token's size and not from its algorithm. From Chromium the match is looser: the control's transfer is up to 0.065 ms higher (0.651 against 0.586 ms for SLH-DSA-SHA2-128f), in a client where EdDSA's same-size token differs from ES256's by 0.044 ms. The control's own split ("Control" columns: control - ES256 as token size, configuration - control as verification) overstates the size effect, though, and gives negative verification differences, because a padded token is not just a larger ES256 token. Its payload is the large part, so `verify_token` spends longer decoding and parsing it (0.405 ms against 0.050 ms for ES256's own token, from http.client at concurrency 1), and the verify response echoes the `pad` claim, so the response body is 17,478 bytes instead of 449. The components of that cell show where the control's time goes:

| Cell (http.client, concurrency 1) | Token bytes | Response body bytes | Total | Transfer | Other handling | Verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ES256 token | 208 | 429 | 0.195 | 0.133 | 0.012 | 0.050 |
| ML-DSA-44 token | 3,355 | 436 | 0.224 | 0.156 | 0.013 | 0.055 |
| ML-DSA-44 size control | 3,355 | 2,800 | 0.278 | 0.155 | 0.019 | 0.105 |
| SLH-DSA-SHA2-128s token | 10,613 | 449 | 0.419 | 0.281 | 0.016 | 0.122 |
| SLH-DSA-SHA2-128s size control | 10,612 | 8,246 | 0.531 | 0.281 | 0.035 | 0.215 |
| SLH-DSA-SHA2-128f token | 22,922 | 449 | 0.690 | 0.359 | 0.019 | 0.313 |
| SLH-DSA-SHA2-128f size control | 22,922 | 17,478 | 0.829 | 0.370 | 0.054 | 0.405 |

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
| ML-DSA-44 | 3,511 | 3,147 | +0.252 | +2.518 | +25.176 | +0.004 |
| SLH-DSA-SHA2-128s | 10,769 | 10,405 | +0.832 | +8.324 | +83.240 | +0.072 |
| SLH-DSA-SHA2-128f | 23,078 | 22,714 | +11.817 | +68.171 | +281.712 | +0.263 |

On every profile, the modeled transfer difference is larger than the measured verification difference: by 12× for SLH-DSA-SHA2-128s and 45× for SLH-DSA-SHA2-128f on the fastest profile, and by three orders of magnitude or more on the slowest. SLH-DSA-SHA2-128f's 23,078-byte request no longer fits in the initial window, so it also costs a full extra round trip. ML-DSA-44's 3,147 extra bytes add 0.25–25 ms against 0.004 ms of extra verification. For these profiles, this answers transport question 4: transfer matters more than verification for every post-quantum configuration. On a connection whose congestion window has already grown, the extra round trip disappears, but the serialization time does not.

## Reproduce

From a clean checkout with the environment from [TRANSPORT.md](TRANSPORT.md#setup), and with no other load on the machine (ephemeral ports are shared by every process, so another heavy client can exhaust them during the run):

```bash
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir results/load/<YYYYMMDDTHHMMSSZ>-macos
# the same workload from this run's saved settings:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --settings results/load/20261117T035444Z-macos/load.json --output-dir results/load/<YYYYMMDDTHHMMSSZ>-macos
# or, with TRANSPORT_ENV set:
make load LOAD_DIR=results/load/<YYYYMMDDTHHMMSSZ>-macos
```

The run took about 2.5 minutes. `--output-dir` must not exist yet or be empty. `--settings` reuses every setting in `load.json` (configurations, transport, clients, claims, concurrency, duration, warm-up, reference, size controls, timeout, nginx buffers, and the upstream keepalive count). The tables in this document come from `results` and `comparisons` in `load.json`, and each cell's counts, medians, p95, and means can be recomputed from its rows in `raw.csv.gz` (`gzip -dc raw.csv.gz`). [TRANSPORT.md](TRANSPORT.md#the-load-command) describes every option, field, and column.

## Limitations

- **Loopback only.** Every measurement ran over loopback on one machine, so the measured transfer component has no real network bandwidth or round trips in it: it is copying and parsing in the client, nginx, and waitress. The network cost of a token is only calculated, in [Modeled network cost](#modeled-network-cost).
- **One machine, one run.** These numbers are from one run on the Mac. The WSL2 run has not been done yet. Run-to-run variation was not measured; within this run, EdDSA's differences from ES256, whose token is the same size, show the noise level (under 0.001 ms from http.client at concurrency 1, up to 0.11 ms from Chromium at concurrency 4). Which desktop applications were open was not recorded.
- **Shortened duration.** Each cell measured 2 seconds instead of the default 5, to keep `raw.csv.gz` under 10 MiB. Every cell still had at least 1,770 verified requests.
- **Not nginx's default upstream connections.** `--upstream-keepalive 64` was needed on macOS and removes nginx's per-request connection to waitress from every request's time, for every configuration alike. Without it, the absolute latencies would be higher, and a sustained run on macOS fails within seconds.
- **Raised header buffers.** The SLH-DSA tokens reach the application only with `--header-buffers 32k`; at nginx's default limits they are rejected (S2-05).
- **Coarse browser timer.** Chromium coarsens `performance.now()` to about 0.1 ms in a page that is not cross-origin isolated, so the browser's medians and p95 values are multiples of 0.1 ms and single requests can show a transfer component below zero. Its means and differences of means average over thousands of requests.
- **Size controls are not pure size.** A padded control has a large payload, which makes `verify_token` and the response larger (the response echoes the `pad` claim; `bytes.response_body` in `load.json` records it), so the control check confirms the transfer component but overstates the size effect of its own total.
- **Concurrency 4 mixes in queueing.** At concurrency 4, time spent waiting for other requests in waitress's single Python process is counted in transfer, so the token-size share there includes queueing behind larger requests.
- **One request type, one claims fixture, HTTP/1.1 without TLS.** Only `GET /api/token/verify` with the minimal claims fixture and a Bearer header was measured, over plain HTTP/1.1; cookies, larger claim sets, HTTPS, and HTTP/2 are not covered here (S3-02 and S3-04).

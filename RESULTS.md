# Sprint 1 results: local signature benchmark

First comparison of all six JWT signature configurations, run with identical settings on two machines (see [Environment](#environment)). Every number below comes from one of these runs:

| Machine | Run | Files |
| --- | --- | --- |
| WSL2 (x86_64) | [`20261103T181323053798Z`](results/20261103T181323053798Z/) | [summary.json](results/20261103T181323053798Z/summary.json), [raw.csv](results/20261103T181323053798Z/raw.csv), [run.json](results/20261103T181323053798Z/run.json) |
| Apple M5 Pro (arm64) | [`20261103T213538864472Z`](results/20261103T213538864472Z/) | [summary.json](results/20261103T213538864472Z/summary.json), [raw.csv](results/20261103T213538864472Z/raw.csv), [run.json](results/20261103T213538864472Z/run.json) |

`summary.json` has sizes, medians, and p95 for each algorithm; `raw.csv` has all 12,000 measured operations in nanoseconds; `run.json` has the settings and environment.

## Results

Default claims fixture ([fixtures/claims.json](fixtures/claims.json)): 63-byte payload. Both runs used 1,000 measured iterations and 100 warm-up iterations per algorithm; the Apple Silicon run reused the WSL2 run's `run.json` with `--settings`. Times are in milliseconds. p95 uses the nearest-rank method. Signature and JWT sizes were identical on both machines.

| Algorithm | Standard | Signature bytes | JWT bytes | Sign median, WSL2 | Sign median, M5 Pro | Sign p95, WSL2 | Sign p95, M5 Pro | Verify median, WSL2 | Verify median, M5 Pro | Verify p95, WSL2 | Verify p95, M5 Pro |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 (RSA-2048) | RFC 7518 | 256 | 464 | 0.642 | 0.289 | 1.021 | 0.324 | 0.036 | 0.009 | 0.130 | 0.012 |
| ES256 (P-256) | RFC 7518 | 64 | 208 | 0.027 | 0.011 | 0.051 | 0.012 | 0.071 | 0.030 | 0.103 | 0.033 |
| EdDSA (Ed25519) | RFC 8037 | 64 | 208 | 0.038 | 0.013 | 0.054 | 0.015 | 0.119 | 0.032 | 0.144 | 0.038 |
| ML-DSA-44 | FIPS 204 | 2,420 | 3,355 | 0.560 | 0.168 | 1.792 | 0.544 | 0.147 | 0.043 | 0.198 | 0.049 |
| SLH-DSA-SHA2-128s | FIPS 205 | 7,856 | 10,613 | 348.229 | 92.341 | 413.439 | 93.563 | 0.345 | 0.100 | 0.511 | 0.110 |
| SLH-DSA-SHA2-128f | FIPS 205 | 17,088 | 22,922 | 16.875 | 4.434 | 20.344 | 4.574 | 0.982 | 0.276 | 1.398 | 0.297 |

Key generation was timed once per algorithm and is a single sample, not a distribution:

| Machine | RS256 | ES256 | EdDSA | ML-DSA-44 | SLH-DSA-SHA2-128s | SLH-DSA-SHA2-128f |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| WSL2 | 56.3 ms | 0.15 ms | 0.11 ms | 0.25 ms | 45.5 ms | 0.98 ms |
| M5 Pro | 8.25 ms | 0.09 ms | 0.05 ms | 0.24 ms | 12.2 ms | 0.20 ms |

## Observations

The first four observations use the WSL2 run; the last compares the two machines.

- **Size (RQ1):** Compared with ES256 (208 bytes), the ML-DSA-44 JWT is 16× larger, SLH-DSA-128s is 51× larger, and SLH-DSA-128f is 110× larger. ML-DSA-44 is the only post-quantum token under the commonly cited 4,096-byte cookie threshold, and only by 741 bytes before the cookie name, attributes, and any extra claims. Both SLH-DSA tokens are well over it.
- **Signing (RQ3):** ML-DSA-44 signs at about the same median speed as RSA-2048 (0.56 vs 0.64 ms). SLH-DSA is much slower: the 128f median is 26× RSA's and the 128s median is 542× RSA's. At roughly 0.35 s per signature on one core, SLH-DSA-128s is a poor fit for issuing tokens per request or per login.
- **Verification (RQ3):** Every configuration verifies in about 1 ms or less. ML-DSA-44 is about 4× RSA and 2× ES256. SLH-DSA-128f is the slowest, at about 1 ms. Verification is the operation repeated on every authenticated request, so in this measurement its cost is small next to the size cost.
- **The SLH-DSA variants trade off:** 128s produces a token half the size, but signing is about 21× slower than 128f.
- **Apple Silicon versus WSL2:** Every median is 2.2–3.8× faster for signing and 2.4–3.9× faster for verification on the M5 Pro, and the ordering of the algorithms is the same. The ratios between algorithms move, though: on the M5 Pro, ML-DSA-44 signs 1.7× faster than RSA-2048 instead of at about the same speed; SLH-DSA-128s signing is 320× RSA's instead of 542×; and ML-DSA-44 verification is 1.4× ES256 instead of 2×. SLH-DSA-128s still takes about 92 ms per signature, too slow for per-request issuance, and the 128s/128f signing ratio stays at about 21×. ML-DSA-44's signing p95 is 3.2× its median on both machines, which points to the variable-time rejection loop in ML-DSA signing rather than measurement noise.

## Reproduce

From a clean checkout (see the [README](README.md) for environment setup):

```bash
conda activate crypto
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/benchmark.py --iterations 1000 --warmup 100
# or repeat this run's exact settings:
python scripts/benchmark.py --settings results/20261103T181323053798Z/run.json
```

`--settings` writes a new run directory; it does not overwrite the run it reads.

The run took about 7 minutes on the WSL2 machine and under 2 minutes on the M5 Pro, almost all of it SLH-DSA-SHA2-128s signing. Add `--iterations-per-algorithm SLH-DSA-SHA2-128s=200` for a shorter run.

## Environment

Both machines used Python 3.15.2 with cryptography 50.0.2, PyJWT 2.15.1, pqcrypto 1.0.0, and OpenSSL 4.0.3.

| | WSL2 run | Apple Silicon run |
| --- | --- | --- |
| OS | Linux 6.6.87.2 (WSL2) | macOS 26.5.1 |
| CPU | x86_64, 8 logical CPUs | Apple M5 Pro (arm64), 18 cores in two performance levels (6 + 12) |
| Commit | `039e9e4` | `e36a3fb` (no changes to `scripts/` or `fixtures/` since `039e9e4`) |
| Uncommitted changes to `scripts/` or `fixtures/` | None | None |
| Power | Not recorded | Battery, Low Power Mode off |

## Limitations

- **One run on each of two machines.** There was no CPU pinning or frequency control, and no repeated runs to measure run-to-run variability. Treat differences of less than about 2× between classical algorithms as unresolved; the cross-machine ratio shifts above are within that range. The machines differ in CPU architecture, OS, and virtualization (WSL2), so their timing differences cannot be attributed to any one of these. macOS schedules threads across its two core types itself and offers no core pinning, so the core type used for the M5 Pro run was not controlled.
- **Raw signature operations only.** Times exclude JOSE encoding/decoding, base64url, claim validation, key loading, and HTTP. They are sequential, on one thread, with no throughput or concurrency measurement.
- **Backends differ.** The classical algorithms and ML-DSA-44 use `cryptography`/OpenSSL. SLH-DSA uses `pqcrypto`, which wraps PQClean's reference-style C code. Part of the SLH-DSA cost may come from the implementation rather than the algorithm.
- **Experimental identifiers.** `SLH-DSA-SHA2-128s` and `SLH-DSA-SHA2-128f` are this project's identifiers and are not IANA-registered. `ML-DSA-44` follows RFC 9964.
- **One small payload (63 bytes).** Larger claim sets add to every token equally, but by a smaller fraction of the post-quantum tokens' size.
- The security levels are not equivalent: RSA-2048 is about 112-bit classical, and the others target NIST category 1 / 128-bit.

## Questions for transport testing

Sprint 2 covers questions 1–3 and Sprint 3 covers questions 4 and 5; see [PROGRESS.md](PROGRESS.md).

1. With realistic claims, a cookie name, and cookie attributes, does an ML-DSA-44 cookie still fit within browsers' per-cookie limit? How much claim headroom is left?
2. For a 10.6 KB or 22.9 KB token, which layer rejects it first? Candidates are the browser cookie jar, the reverse proxy's header buffers (for example nginx `large_client_header_buffers`), or the application server's header limits. What status or behavior does each produce?
3. Does `Authorization: Bearer` succeed where cookies fail, and at what size does it also hit proxy or server header limits?
4. End to end, does the extra transfer for larger tokens matter more than the verification differences measured here?
5. Mitigations: can splitting the cookie or using reference tokens bring SLH-DSA tokens within limits, and how much latency does a reference-token lookup add?

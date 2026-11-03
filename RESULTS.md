# Sprint 1 results: local signature benchmark

First comparison of all six JWT signature configurations. Every number below comes from run [`20261103T181323053798Z`](results/20261103T181323053798Z/):

- [summary.json](results/20261103T181323053798Z/summary.json): sizes, medians, and p95 for each algorithm
- [raw.csv](results/20261103T181323053798Z/raw.csv): all 12,000 measured operations, in nanoseconds
- [run.json](results/20261103T181323053798Z/run.json): settings and environment

## Results

Default claims fixture ([fixtures/claims.json](fixtures/claims.json)): 63-byte payload. The run used 1,000 measured iterations and 100 warm-up iterations per algorithm. Times are in milliseconds. p95 uses the nearest-rank method.

| Algorithm | Standard | Signature bytes | JWT bytes | Sign median | Sign p95 | Verify median | Verify p95 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 (RSA-2048) | RFC 7518 | 256 | 464 | 0.642 | 1.021 | 0.036 | 0.130 |
| ES256 (P-256) | RFC 7518 | 64 | 208 | 0.027 | 0.051 | 0.071 | 0.103 |
| EdDSA (Ed25519) | RFC 8037 | 64 | 208 | 0.038 | 0.054 | 0.119 | 0.144 |
| ML-DSA-44 | FIPS 204 | 2,420 | 3,355 | 0.560 | 1.792 | 0.147 | 0.198 |
| SLH-DSA-SHA2-128s | FIPS 205 | 7,856 | 10,613 | 348.229 | 413.439 | 0.345 | 0.511 |
| SLH-DSA-SHA2-128f | FIPS 205 | 17,088 | 22,922 | 16.875 | 20.344 | 0.982 | 1.398 |

Key generation was timed once per algorithm and is a single sample, not a distribution: RS256 56.3 ms, ES256 0.15 ms, EdDSA 0.11 ms, ML-DSA-44 0.25 ms, SLH-DSA-SHA2-128s 45.5 ms, SLH-DSA-SHA2-128f 0.98 ms.

## Observations

- **Size (RQ1):** Compared with ES256 (208 bytes), the ML-DSA-44 JWT is 16× larger, SLH-DSA-128s is 51× larger, and SLH-DSA-128f is 110× larger. ML-DSA-44 is the only post-quantum token under the commonly cited 4,096-byte cookie threshold, and only by 741 bytes before the cookie name, attributes, and any extra claims. Both SLH-DSA tokens are well over it.
- **Signing (RQ3):** ML-DSA-44 signs at about the same median speed as RSA-2048 (0.56 vs 0.64 ms). SLH-DSA is much slower: the 128f median is 26× RSA's and the 128s median is 542× RSA's. At roughly 0.35 s per signature on one core, SLH-DSA-128s is a poor fit for issuing tokens per request or per login.
- **Verification (RQ3):** Every configuration verifies in about 1 ms or less. ML-DSA-44 is about 4× RSA and 2× ES256. SLH-DSA-128f is the slowest, at about 1 ms. Verification is the operation repeated on every authenticated request, so in this measurement its cost is small next to the size cost.
- **The SLH-DSA variants trade off:** 128s produces a token half the size, but signing is about 21× slower than 128f.

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

The run took about 7 minutes, almost all of it SLH-DSA-SHA2-128s signing. Add `--iterations-per-algorithm SLH-DSA-SHA2-128s=200` for a shorter run.

## Environment

- Python 3.15.2 on Linux 6.6.87.2 (WSL2), x86_64, 8 logical CPUs
- cryptography 50.0.2, PyJWT 2.15.1, pqcrypto 1.0.0, OpenSSL 4.0.3
- Commit `039e9e4`, with no uncommitted changes to `scripts/` or `fixtures/`

## Limitations

- **Single run on one machine under WSL2.** There was no CPU pinning or frequency control, and no repeated runs to measure run-to-run variability. Treat differences of less than about 2× between classical algorithms as unresolved.
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

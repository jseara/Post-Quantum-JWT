# CIS628Project: Post-Quantum JWT Benchmarking

This project investigates how post-quantum digital signatures affect JSON Web Tokens (JWTs) and the web infrastructure that carries them. We will compare classical RSA and ECDSA signatures with ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), measuring token size, cryptographic performance, and practical transport limits.

The final deliverable is a reproducible authentication test environment and experimental results covering token size, signing and verification time, throughput, request latency, and possible mitigations for oversized tokens.

## Project status

Sprint 1 is complete. Classical baselines are implemented in [scripts/rsa_jwt.py](scripts/rsa_jwt.py), [scripts/es256_jwt.py](scripts/es256_jwt.py), and [scripts/ed25519_jwt.py](scripts/ed25519_jwt.py). Token generation and verification for ML-DSA-44 and both SLH-DSA-SHA2-128 variants are described below. A combined benchmark runner covers all six configurations, and the first measured comparison is in [RESULTS.md](RESULTS.md). [PROGRESS.md](PROGRESS.md) plans Sprint 2 (where large tokens break in cookie and Bearer transport) and Sprint 3 (end-to-end cost and mitigations). Project context is in [AGENTS.md](AGENTS.md).

The Sprint 2 transport stack (Playwright with Chromium, nginx, and waitress) is described in [TRANSPORT.md](TRANSPORT.md), with each layer's version and documented default limits, pinned setup for macOS and WSL2, a check that sends one browser request through the proxy to the application, and a `tokens` check that sends every configuration's token through it as a cookie and as a Bearer header. The measured cookie and Bearer size boundaries are in [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md). End-to-end latency and throughput of authenticated requests through the same stack (Sprint 3, S3-01), split into token transfer, verification, and other server handling, are in [END_TO_END_RESULTS.md](END_TO_END_RESULTS.md). The first S3-02 mitigation, smaller claim sets, is in [MITIGATION_RESULTS.md](MITIGATION_RESULTS.md): how much each configuration's token shrinks with only the five required OpenID Connect claims, whether that moves any Sprint 2 size limit, and its latency under the S3-01 workload. The second, cookie splitting, is in [MITIGATION_RESULTS.md](MITIGATION_RESULTS.md#cookie-splitting) too: which limits a token split into `jwt.<index>.<count>` cookies still runs into, how the application handles missing or reordered chunks, and what splitting costs in latency. The third, reference tokens, is in [MITIGATION_RESULTS.md](MITIGATION_RESULTS.md#reference-tokens) as well: the request sizes and size limits of a 47-byte reference sent in place of the JWT, how the application handles unknown, expired, and revoked references and a stopped reference store, and what looking the token up costs in latency.

Sprint 3's comparison and recommendations (S3-03) are in [RECOMMENDATIONS.md](RECOMMENDATIONS.md): tables comparing Sprint 1's signing times, S3-01's end-to-end latency and throughput, the size limits, and each mitigation's latency, throughput, and calculated network cost, with links to the raw data and settings, and recommendations for RQ4 on which configuration and mitigation fit which deployment and what each trades off. Its tables are generated from the committed results by [scripts/transport_report.py](scripts/transport_report.py), which needs only the standard library; `scripts/transport_report.py --check` confirms that the document matches the results, and `--write` regenerates the tables.

S3-04 repeats Sprint 2's cookie and Bearer sweeps over HTTPS and HTTP/2 with a per-run self-signed certificate and experiment key, and compares every boundary with the plain-HTTP runs in [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md#https-and-http2-s3-04): TLS moved nothing, while over HTTP/2 nginx's header limit counts HPACK-encoded bytes, so Chromium's Bearer tokens get further at the defaults.

The browser test page ([transport/static/index.html](transport/static/index.html)) also works without the stack: on GitHub Pages, or opened from disk, it is read-only, and its buttons replay the committed results and show the comparison tables. [TRANSPORT.md](TRANSPORT.md#the-test-pages-read-only-mode) explains the mode and the Pages workflow.

## Make shortcuts

The [Makefile](Makefile) wraps the common commands; run `make` for the list. With the environment active (`conda activate crypto`), or with `TRANSPORT_ENV` set as in [TRANSPORT.md](TRANSPORT.md#setup):

```bash
make serve    # nginx on http://localhost:8080 in front of the app on 8081; Ctrl+C stops both
make logs     # in a second terminal: follow nginx's access and error logs and app.log
make tokens   # send every configuration's token through the stack as a cookie and a Bearer header
make sweep    # cookie and Bearer size sweeps of all six configurations; results in results/transport/<time>/
make load     # end-to-end latency and throughput of all six configurations; results in results/load/<time>/
make claims   # smaller claim sets (oidc vs essential): token sizes, size limits, latency; results in results/claims/<time>/
make cookies   # cookie splitting (jwt cookie vs split chunks): size limits, chunk handling, latency; results in results/cookies/<time>/
make refs      # reference tokens (Bearer JWT vs reference): size limits, reference handling, lookup latency; results in results/refs/<time>/
make protocols # cookie and Bearer sweeps over HTTPS and HTTP/2, compared with Sprint 2's plain HTTP; results in results/transport/<time>/
make test     # full test suite
```

`make serve` keeps its nginx config and logs in `.transport-run/` (ignored by git) and empties it at each start. Ports and the interpreter can be overridden, for example `make serve PROXY_PORT=9090 APP_PORT=9091 PYTHON=/path/to/python`. From WSL2, the Windows browser reaches the stack at `http://localhost:8080/`. That page is a dashboard with buttons for each configuration: issue the token as a cookie or in the response body, verify the cookie, or send the token as a Bearer header. Each result shows the status and which layer answered (application, nginx, or waitress), and why a request was rejected. The page sends no request until a button is clicked, so it does not disturb `make check` or `make tokens`, which load the same page.

## Run the RSA baseline

Use the existing `crypto` conda environment and install the pinned Python dependencies:

```bash
conda activate crypto
python -m pip install -r requirements.txt
python scripts/rsa_jwt.py
```

If creating the environment on another machine, run `conda create -n crypto python=3.15 pip` first. The initial implementation was checked with Python 3.15.2.

The script generates an ephemeral 2,048-bit RSA key, creates and verifies an RS256 JWT using [fixtures/claims.json](fixtures/claims.json), and prints only the token by default. Add `--verbose` (or `-v`) to print the full JSON report. Keys stay in memory. The fixed fixture has no expiration or other time-dependent claims so later algorithms can use the same payload. Verification still checks expiration when an `exp` claim is supplied. These fixtures are for experiments.

Configure the run or save the report:

```bash
python scripts/rsa_jwt.py --verbose
python scripts/rsa_jwt.py --iterations 1000 --warmup 100 --output results/rsa-2048.json
python scripts/rsa_jwt.py --key-size 3072 --iterations 100
python scripts/rsa_jwt.py --claims fixtures/claims.json
python -m unittest discover -s tests -v
```

Run these commands from the repository root. The default fixture is resolved relative to the script, so it also works when launched from another directory. `--claims` and `--output` paths are relative to the working directory. `--output` always saves the full report; console output still follows `--verbose`. Supported key sizes are 2,048, 3,072, and 4,096 bits; measured iterations must be positive and warm-up may be zero.

The report includes decoded payload bytes, raw signature bytes, complete JWT bytes, per-iteration signing/verification times in nanoseconds, median and nearest-rank p95 in milliseconds, and environment metadata. Timings cover raw RSA operations over the prepared JWT signing input. Key generation is reported separately; JWT serialization, parsing, claim validation, and file output are excluded from signing/verification timings. Every measured signature is verified. This is a local sequential benchmark; it does not measure HTTP latency or concurrent throughput.

The implementation uses [PyJWT's RS256 support](https://pyjwt.readthedocs.io/en/stable/usage.html) and [cryptography's RSA primitives](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/). Correctness checks cover valid tokens, payload/signature tampering, wrong keys, disallowed algorithms, and expired claims.

## Run the ES256 baseline

Use the same `crypto` environment and dependencies as RSA:

```bash
python scripts/es256_jwt.py
python scripts/es256_jwt.py --verbose
python scripts/es256_jwt.py --iterations 1000 --warmup 100 --output results/es256.json
python -m unittest discover -s tests -p 'test_es256_jwt.py' -v
```

The script uses [PyJWT's ES256 support](https://pyjwt.readthedocs.io/en/stable/algorithms.html) with an ephemeral P-256 key, SHA-256, and the same claims fixture and options as the Ed25519 script (`--claims`, `--iterations`, `--warmup`, `--verbose`, `--output`). The curve is fixed, so there is no `--key-size` option. The report records `algorithm: ES256`, `curve: P-256`, and `hash: SHA-256`.

JWS requires ECDSA signatures as the fixed-width 64-byte `R || S` concatenation ([RFC 7518, section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)), while `cryptography` produces variable-length DER. The reported signature size is the 64-byte JOSE form from the token. Timed operations use the DER form directly, so the DER ↔ `R || S` conversion is excluded from timings along with key generation and JWT encoding/decoding. ECDSA signing is randomized, so each run produces a different signature. Besides the checks shared with RSA and Ed25519, the tests confirm that a DER-encoded signature in the token is rejected.

## Run the Ed25519 baseline

Use the same `crypto` environment and dependencies as RSA:

```bash
python scripts/ed25519_jwt.py
python scripts/ed25519_jwt.py --verbose
python scripts/ed25519_jwt.py --iterations 1000 --warmup 100 --output results/ed25519.json
python -m unittest discover -s tests -p 'test_ed25519_jwt.py' -v
```

The script uses [PyJWT's EdDSA support](https://pyjwt.readthedocs.io/en/stable/usage.html#encoding-decoding-tokens-with-eddsa-ed25519) with an Ed25519 key and the same claims fixture as RSA. It prints only the token by default; `--verbose` (or `-v`) prints the full report, and `--output` saves that report independently. It also accepts `--claims`, `--iterations`, and `--warmup`. Ed25519 has a fixed configuration, so there is no `--key-size` option. Keys stay in memory, and signing/verification timings exclude key generation and JWT encoding/decoding just as in the RSA script. The report records `algorithm: EdDSA` and `curve: Ed25519`.

## Try an ML-DSA-44 token

With the same dependencies installed in `crypto`, generate one token:

```bash
python scripts/mldsa_jwt.py
python scripts/mldsa_jwt.py --claims fixtures/claims.json
python -m unittest discover -s tests -p 'test_mldsa_jwt.py' -v
```

This script uses the shared claims and prints only a compact signed JWT. It generates a fresh in-memory key for each run and does not save it. There are no benchmark loops or timing reports. Since the installed PyJWT does not provide this algorithm, the script assembles the compact JWS directly and uses `cryptography` for signing. It uses `alg: ML-DSA-44`, a raw signature encoded with base64url, and an empty signing context as specified in [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html#section-5). `verify_token` in the same module verifies these tokens through the shared [scripts/compact_jws.py](scripts/compact_jws.py) parser: it accepts only `alg: ML-DSA-44`, uses strict unpadded base64url, and rejects expired tokens when an `exp` claim is supplied. Failures raise PyJWT's exception types (`InvalidSignatureError`, `InvalidAlgorithmError`, `ExpiredSignatureError`, `DecodeError`), so callers handle these tokens the same way as the classical baselines. No other registered claims are validated.

## Try SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f tokens

Install the added dependency in `crypto`, then run either script:

```bash
python -m pip install -r requirements.txt
python scripts/slhdsa_sha2_128s_jwt.py
python scripts/slhdsa_sha2_128f_jwt.py
python -m unittest discover -s tests -p 'test_slhdsa_jwt.py' -v
```

Each script generates a fresh in-memory key, signs the shared claims, and prints only the compact token. Both accept `--claims path/to/claims.json`. They use [pqcrypto 1.0.0's finalized SLH-DSA implementations](https://pypi.org/project/pqcrypto/1.0.0/) with an empty context and no pre-hash mode. There are no benchmark loops, timing reports, or saved keys. Each module also provides `verify_token`, which uses the same parser and exceptions as ML-DSA-44 and accepts only its own `alg` value.

The `alg` values `SLH-DSA-SHA2-128s` and `SLH-DSA-SHA2-128f` are experimental identifiers for this project; they are not currently registered in the [IANA JOSE registry](https://www.iana.org/assignments/jose/). The compact JWS is assembled directly; standard JWT libraries need an adapter to verify these tokens. With the default claims, token sizes are 10,613 bytes for `128s` and 22,922 bytes for `128f`. The `s` variant prioritizes signature size and the `f` variant prioritizes signing speed.

## Run the combined benchmark

[scripts/benchmark.py](scripts/benchmark.py) runs every configuration through the common interface in [scripts/algorithms.py](scripts/algorithms.py), which wraps each script's `create_token`/`verify_token` and adds key generation, raw signing/verification, and algorithm metadata:

```bash
python scripts/benchmark.py
python scripts/benchmark.py --iterations 1000 --warmup 100 --iterations-per-algorithm SLH-DSA-SHA2-128s=200
python scripts/benchmark.py --algorithms ML-DSA-44 SLH-DSA-SHA2-128s --output-dir results/pq-only
python scripts/benchmark.py --settings results/<run_id>/run.json
python -m unittest discover -s tests -v
```

By default it runs all six configurations (RS256, ES256, EdDSA, ML-DSA-44, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f) with 100 measured and 10 warm-up iterations, prints a summary table, and writes a run directory under `results/<run_id>/`. `--settings` reuses a saved run's algorithms, iteration counts, warm-up, and claims file; any other flag given on the command line overrides the saved value. `--iterations-per-algorithm` lowers the count for slow configurations (SLH-DSA-SHA2-128s signing takes hundreds of milliseconds); the count used is recorded for every algorithm.

For each configuration, keys are generated, and a token is created and verified with `verify_token`, before the timed loop. Each iteration then times one raw signature and one raw verification of that signature over the prepared JWT signing input, and every signature is verified. Key generation is timed once and reported separately. JOSE encoding/decoding, warm-up iterations, summary generation, and file output are excluded. Like the individual scripts, this is a local sequential benchmark.

### Benchmark output format

Each run directory contains three files (`schema_version: 1`):

- `run.json`: `run_id`, start/finish times (UTC), `settings` (`algorithms`, `iterations`, `warmup`, `iterations_per_algorithm`, `claims_file`, `claims_sha256`), `measurement_scope`, and `environment` (Python, platform, CPU count, `cryptography`, PyJWT, `pqcrypto` and OpenSSL versions, timer, and the git commit and whether `scripts/` or `fixtures/` had uncommitted changes).
- `raw.csv`: one row per measured operation, with columns `run_id, algorithm, parameter_set, operation, iteration, duration_ns`. `operation` is `sign` or `verify`, and `iteration` starts at 1 after warm-up.
- `summary.json`: per algorithm, the metadata (`algorithm`, `family`, `parameter_set`, `standard`, `jose_spec`, `jose_status`, `backend`), `iterations`, `warmup`, `sizes_bytes` (`payload`: decoded payload bytes, `signature`: raw signature bytes as carried in the token, `jwt`: complete compact token bytes), `key_generation_ms`, `sign` and `verify` (`median_ms`, nearest-rank `p95_ms`, `n`), `verified`, and the sample `token`.

All keys are ephemeral experiment keys held in memory; tokens in results are signed with discarded keys and are not credentials.

## Research questions

1. How large are JWTs signed with ML-DSA and SLH-DSA compared with classical algorithms?
2. Where do large tokens encounter limits in browsers, cookies, HTTP headers, reverse proxies, and application servers?
3. How do the algorithms compare in signing time, verification time, throughput, and end-to-end request latency?
4. How effective are smaller claim sets, cookie splitting, and reference tokens at mitigating these limits, and what tradeoffs do they introduce?

Performance differences are questions to measure; we do not assume every post-quantum operation will be slower or that token size alone explains its cost. The commonly cited 4,096-byte cookie threshold is an experimental boundary to investigate, not a universal JWT size limit. Actual limits and byte accounting depend on the browser and server configuration.

## Algorithms and initial scope

These are **digital signature algorithms**, not encryption algorithms. Signed JWTs provide integrity and authentication; their payloads remain readable. This project studies JWT authentication rather than post-quantum TLS or payload encryption.

| Role | Algorithm | Initial configuration | Purpose |
| --- | --- | --- | --- |
| Classical baseline | RS256 | RSA, 2,048-bit key, SHA-256 | Establish a familiar JWT baseline first. |
| Classical baseline | ES256 | ECDSA, P-256, SHA-256 | Provide a compact classical signature comparison. |
| Additional classical baseline | EdDSA | Ed25519 | Compare another compact classical signature. |
| Post-quantum comparison | ML-DSA, FIPS 204 | ML-DSA-44 | Start with one lattice-based parameter set. |
| Post-quantum comparison | SLH-DSA, FIPS 205 | SLH-DSA-SHA2-128s | Start with one hash-based parameter set. |

RS256 and ES256 are defined in [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html). ML-DSA and SLH-DSA are specified in the final NIST standards [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), respectively. These are standards identifiers; the actual algorithm names and parameter sets must be recorded in every experiment.

The initial configurations provide a manageable starting point, not a claim of equivalent security strength. Additional RSA key sizes and post-quantum parameter sets can be evaluated later. Use existing cryptographic implementations and verify that they implement the finalized algorithms, rather than assuming older Dilithium or SPHINCS+ implementations are interchangeable.

Cryptographic support and JWT library support are separate integration questions. Check the current [IANA JOSE registry](https://www.iana.org/assignments/jose/jose.xhtml) and applicable specifications before choosing post-quantum `alg` values and signature encodings. Document any experimental encoding or library adapter and its interoperability limits.

## Experimental approach

Start with local signing and verification, then extend the same tokens into a browser → reverse proxy/web server → application test environment.

- Use identical serialized claims for each algorithm within a comparison. Keep header fields consistent except for algorithm-specific values.
- Generate keys outside timed signing and verification loops. If key generation is measured, report it separately.
- Measure raw signature bytes and complete compact JWT bytes, including base64url encoding and separators.
- Measure signing and verification separately from token serialization and HTTP request handling.
- Record warm-up, iteration counts, timing units, hardware, operating system, runtime, dependency versions, algorithm configuration, and relevant server limits.
- Preserve raw measurements alongside summaries. Report median and p95 latency, and define the workload and concurrency for any throughput result.
- In transport experiments, send tokens using cookies and `Authorization: Bearer` headers. Vary claim size and record the rejecting layer, status or browser behavior, and configured limits.

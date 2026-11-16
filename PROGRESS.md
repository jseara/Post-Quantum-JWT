## Sprint 1: Establish reproducible algorithm benchmarks

**Sprint goal:** From a clean checkout, generate keys, create and verify signed tokens with both classical baselines and one parameter set from each post-quantum family, and export an initial size and timing comparison.

Build the classical baseline first so the shared fixtures, token format, and measurement harness can be checked before adding post-quantum adapters. Browser and proxy testing follows in Sprint 2.

### S1-01 — Choose and document the implementation stack

- [x] Select the language/runtime, classical JWT library, and post-quantum cryptographic backend after checking support for the initial configurations above.
- [x] Check JOSE algorithm identifiers, encoding requirements, and whether custom adapters are necessary.
- [x] Add dependency/version management and clean-checkout setup instructions, including any native build requirements.

**Done when:** A documented setup works in the supported environment, and a small capability check confirms key generation, signing, and verification for all four configurations. Record any interoperability limitations.

### S1-02 — Define shared fixtures and the algorithm interface

- [x] Add one fixed JWT claim fixture and deterministic JSON serialization for comparable input bytes. Keep time-dependent claim validation separate from static cryptographic measurements.
- [x] Define a common interface for key generation, signing, and verification, with algorithm and parameter-set metadata.
- [x] Specify the benchmark output format, including payload bytes, signature bytes, token bytes, operation, duration, iteration, and run/environment metadata.

**Done when:** Every adapter can consume the same signing input and report results through the same schema. Fixtures and keys used for experiments are clearly distinguished from production credentials.

### S1-03 — Implement the classical JWT baselines

- [x] Implement RS256 with a 2,048-bit RSA key and ES256 with P-256 using established libraries.
- [x] Generate complete compact signed JWTs and verify them, respecting JOSE signature encoding requirements.
- [x] Add correctness checks for a valid token, a changed payload, a changed signature, a wrong verification key, and a disallowed algorithm.

**Done when:** Both baselines pass the correctness checks and produce measured signature and complete token sizes for the shared fixture.

### S1-04 — Integrate ML-DSA and SLH-DSA

- [x] Add ML-DSA-44 and SLH-DSA-SHA2-128s adapters using the selected backend.
- [x] Integrate their signatures into the compact token flow with documented algorithm identifiers and encoding rules.
- [x] Run the same positive and negative correctness checks as the classical adapters, and check signature lengths against the relevant standards.

**Done when:** Both post-quantum configurations create and verify tokens over the shared fixture. Documentation identifies backend versions and any experimental JWT integration. A backend or JOSE blocker must be recorded explicitly rather than substituting an older algorithm silently.

### S1-05 — Build the local benchmark runner

- [x] Add a repeatable command that runs all four configurations with configurable warm-up and measured iterations.
- [x] Measure signing and verification independently with keys and fixtures prepared outside the timed loops; report signature and complete token sizes.
- [x] Export raw timings and run metadata to CSV or JSON, plus median and p95 summaries. Exclude setup, file output, and summary generation from operation timings.

**Done when:** A run produces inspectable raw data and a summary for all four configurations, and its settings can be reused for another run. Do not use timing thresholds as correctness tests.

### S1-06 — Publish the first comparison and reproduction steps

- [x] Run the benchmark in a recorded environment and check that all generated tokens verify.
- [x] Add a small results table comparing signature bytes, JWT bytes, signing latency, and verification latency, with links to the raw data and run settings.
- [x] Document the exact setup and execution commands, measurement limitations, and follow-up questions for transport testing.

**Done when:** Another team member can reproduce the workflow from a clean checkout, and reported results can be traced to a specific configuration and dataset.

**Sprint 1 completion:** All six tasks are complete, all four algorithm configurations pass correctness checks, and the repository contains a runnable benchmark, raw measurements, and an initial comparison. Do not fill result tables with estimates presented as measurements.

## Sprint 2: Find where large tokens break in transport

**Sprint goal:** Send tokens from all six configurations through a browser → reverse proxy → application path, as cookies and as `Authorization: Bearer` headers. Find the size at which each layer rejects them, and publish the limits with evidence.

Sprint 2 answers transport questions 1–3 in [RESULTS.md](RESULTS.md#questions-for-transport-testing) (RQ2). End-to-end cost and mitigations follow in Sprint 3. Test each layer at its default limits first. Raise a limit only to uncover the next layer's limit, and record every change.

### S2-01 — Choose and document the transport stack

- [x] Select the browser automation tool and browser engines, the reverse proxy, and the application server/framework. Start with one of each (for example Playwright with Chromium, nginx, and a Python application server), and add others only after the first path works.
- [x] Record each layer's version and its documented default limits for cookie size, single header size, and total request header size, with sources.
- [x] Add reproducible setup instructions (pinned versions or containers) that work on both macOS and WSL2.

**Done when:** The stack runs from a clean checkout on both team machines, and a table lists every layer with its version and documented limits.

**Status:** Playwright 1.64.1 with Chromium 156.0.8078.4, nginx 1.31.8, and waitress 3.0.2; versions and documented limits are in [TRANSPORT.md](TRANSPORT.md) and [transport/stack.json](transport/stack.json). `bash transport/setup.sh PREFIX` builds the pinned environment; it exited 0 and `scripts/transport_stack.py check` passed on macOS (November 4) and on WSL2 with Ubuntu 24.04.4 (November 12).

### S2-02 — Build the test environment

- [x] Add a minimal application with one endpoint that issues a token as a cookie and one that accepts a token from either a cookie or a Bearer header and verifies it with the adapters in [scripts/algorithms.py](scripts/algorithms.py).
- [x] Put the reverse proxy in front of the application, and serve the test page the browser loads through the proxy.
- [x] Log enough at each layer to tell which one handled or rejected a request: the browser's cookie jar and request headers, the proxy's access and error logs, and the application's log of received header sizes.

**Done when:** A normal-sized token from each of the six configurations verifies at the application as both a cookie and a Bearer header. Sent browser → proxy → application, every token within the default limits verifies, every other token is rejected with the rejecting layer identified, and each layer's log shows every request that reached it.

**Status:** `"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py tokens` sends the fixture token of each configuration through the stack as a cookie and as a Bearer header; endpoints, logs, and results are in [TRANSPORT.md](TRANSPORT.md#the-token-check). On macOS (Apple M5 Pro, November 10, 2026), RS256, ES256, EdDSA, and ML-DSA-44 verified browser → proxy → application on both transports. The SLH-DSA tokens were rejected, as the default limits predict: the SLH-DSA-SHA2-128s cookie by the browser (Chromium did not store it), the SLH-DSA-SHA2-128f cookie by the proxy (502, `upstream sent too big header`), and both Bearer headers by the proxy (400, `client sent too long header line`). All six configurations verified on both transports when sent directly to the application. On WSL2 (Ubuntu 24.04.4, November 12, 2026) the results were the same except the SLH-DSA-SHA2-128s cookie, which the proxy rejected (502, `upstream sent too big header`) because `proxy_buffer_size` is 4 KiB there instead of 16 KiB.

### S2-03 — Generate size-controlled tokens and account for bytes

- [x] Add a realistic claims fixture (for example, typical OpenID Connect ID token claims) alongside the existing minimal fixture.
- [x] Add a deterministic padding claim that produces tokens at target sizes for every configuration, and verify each token before sending it.
- [x] Report, for every request, the token bytes, the cookie bytes (name, value, and attributes), the header line bytes (`Cookie:` or `Authorization: Bearer`), and the total request header bytes.

**Done when:** Any configuration can produce a verified token at a requested size, and the byte accounting for a request can be checked by hand.

**Status:** [fixtures/claims_oidc.json](fixtures/claims_oidc.json) holds 22 typical OpenID Connect claims, and [scripts/token_sizing.py](scripts/token_sizing.py) grows any configuration's token to a requested size (within one byte) with a `pad` claim, computed without signing and checked by signing. The issue endpoint takes `claims`, `pad`, and `attrs`, and verifies every token before issuing it (a 500 instead of a token that fails). Every `sweep` probe records the token, cookie, `Set-Cookie`, upstream response header, `Cookie:` line, and request header bytes; how each is counted is in [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md#byte-accounting). Building it found that the post-quantum verifiers accepted tokens with an `aud` claim that PyJWT rejects; all six adapters now take an `audience` and apply PyJWT's rules.

### S2-04 — Cookie transport sweep

- [x] Sweep token sizes for each configuration, delivered in a cookie set by the application's `Set-Cookie` response. Use coarse steps, then narrow to the exact boundary at each limit found.
- [x] At each size, record whether the browser stored the cookie, whether it sent it, and which layer rejected the request, with the status code or browser behavior. A cookie the browser silently drops counts as a rejection by the browser.
- [x] Measure ML-DSA-44's claim headroom with the realistic claims fixture and typical cookie attributes (`Secure`, `HttpOnly`, `SameSite`, `Path`, `Max-Age`).

**Done when:** For each configuration, the largest cookie-carried token that reaches the application is known, along with the first layer that rejects a larger one and the evidence.

**Status:** Measured on WSL2 on November 13, 2026, at nginx's default buffers and with `--proxy-buffers 16k` (the Mac's defaults); results and evidence are in [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md). At WSL2's defaults nginx rejects first, once the application's response header block reaches 4,096 bytes (a 3,916-byte token); with 16k buffers Chromium does, above 4,096 bytes of cookie name + value. Neither SLH-DSA parameter set fits at any size. With OIDC claims and production cookie attributes, ML-DSA-44's headroom is negative: its 4,095-byte token is 2 bytes over Chromium's limit, so 2 fewer bytes of claims would fit and the verdict depends on the fixture's exact values. The sweep has not been run on macOS.

### S2-05 — Bearer header transport sweep

- [x] Repeat the sweep with the token in an `Authorization: Bearer` header, sent both from the browser (`fetch`) and from a non-browser HTTP client, to separate browser limits from server limits.
- [x] Record the first rejecting layer and its response at each boundary, and compare the boundaries with the cookie results.
- [x] Raise the first rejecting layer's limit once, rerun, and record the next layer's limit and the configuration change.

**Done when:** For each configuration, the largest Bearer-carried token that reaches the application is known for both clients, and the next limit behind the first one is recorded.

**Status:** Measured on WSL2 on November 13, 2026 with `sweep --transport bearer`, from Chromium and from http.client; results in [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md#bearer-header-boundaries). At the defaults nginx rejects first for both clients, with 400, once the `Authorization` line reaches 8,192 bytes (an 8,168-byte token), so Bearer carries about twice what a cookie does; neither SLH-DSA parameter set fits. Raised once with `--header-buffers 512k`, the next limit is waitress's 262,144-byte request header total (431), at about 261.5 KB of token from Chromium and 262.0 KB from http.client; every configuration fits below it. Chromium sent 262,168 bytes of request headers without error.

### S2-06 — Publish the transport results

- [x] Add a results document with a table per transport giving, for every configuration, the size boundary, the rejecting layer, its status or behavior, and its configured limit.
- [x] Link each result to its raw data, logs, and the exact configuration of every layer.
- [x] Document the reproduction steps, limitations (engines and versions tested, default versus raised limits), and follow-up questions for Sprint 3.

**Done when:** Another team member can reproduce the sweeps from a clean checkout, and every reported boundary can be traced to raw evidence.

**Status:** [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md) has a table per transport with every configuration's boundary, rejecting layer, and status or behavior, a comparison with each configured limit, byte accounting, links to every run's `sweep.json`, logs, and rendered `nginx.conf`, the commands to reproduce each run, limitations, and questions for Sprint 3. All runs so far are from WSL2; the Mac has not rerun the sweeps.

**Sprint 2 completion:** All six tasks are complete, and every configuration has measured cookie and Bearer boundaries with the rejecting layer identified. Do not report documented limits as measured boundaries.

## Sprint 3: Measure end-to-end cost and mitigations

**Sprint goal:** Measure whether token size matters more end to end than verification cost, and test whether mitigations bring oversized tokens within the limits found in Sprint 2.

Sprint 3 answers transport questions 4 and 5 in [RESULTS.md](RESULTS.md#questions-for-transport-testing) (RQ3 at the HTTP level, and RQ4). Refine these tasks once Sprint 2's limits are known.

### S3-01 — Measure end-to-end latency and throughput

- [ ] Define the workload (request mix, concurrency, duration, and where the client runs) and record it with every run.
- [ ] Measure request latency (median and p95) and throughput for every configuration through the Sprint 2 path, separating token transfer, verification, and other server handling.

**Done when:** For each configuration, the results show how much of the end-to-end difference comes from token size and how much from verification.

### S3-02 — Compare mitigations

- [ ] Smaller claim sets: measure how much each configuration's token shrinks with only essential claims, and whether that moves any Sprint 2 boundary.
- [ ] Cookie splitting: split oversized tokens across several cookies and reassemble them in the application. Record the per-cookie, cookie-count, and total header limits it runs into, and how it handles missing or reordered chunks.
- [ ] Reference tokens: replace the JWT in transit with a short opaque reference and look up the signed token on the server. Measure the lookup latency, and note what the design gives up, such as stateless and offline verification.

**Done when:** Each mitigation has run under the S3-01 workload, with its effect on the size limits and on latency recorded.

### S3-03 — Publish the end-to-end and mitigation results

- [ ] Add tables comparing end-to-end latency and throughput, and each mitigation's effect, with links to the raw data and settings.
- [ ] Summarize recommendations for RQ4: which configuration and mitigation fit which deployment, and what each trades off.

**Done when:** The results are reproducible from a clean checkout, and every recommendation can be traced to a measurement.

### S3-04 — Repeat the transport sweeps over HTTPS and HTTP/2

- [ ] Add a TLS option to the stack: a self-signed certificate for `127.0.0.1` and `localhost` generated into the run directory with `cryptography`, `listen ... ssl` in the rendered nginx configuration, and Playwright set to accept the certificate. The pinned nginx build already has `--with-http_ssl_module` and `--with-http_v2_module`.
- [ ] Rerun the S2-04 cookie and S2-05 Bearer sweeps over HTTPS with HTTP/1.1, and check that the boundaries match the plain-HTTP results, as expected when TLS only encrypts the same header bytes.
- [ ] Rerun them over HTTP/2 (`http2 on;`), where header compression (HPACK) changes how nginx and Chromium apply their limits, and record each boundary that moves and the layer and limit responsible. HTTP/3 is out of scope: the nginx build has no `http_v3` module.

**Done when:** For each configuration and transport, the cookie and Bearer boundaries over HTTPS/HTTP/1.1 and over HTTP/2 are measured and compared with Sprint 2's plain-HTTP boundaries, with the evidence linked.

## Follow-up backlog

- **Expanded comparisons:** Add further parameter sets and repeat runs to assess variability and the tradeoffs among signature size, speed, and security strength.
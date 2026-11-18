# Sprint 3 results: mitigations

Mitigations for the token sizes that break transport in Sprint 2, measured through the same stack, Chromium or http.client → nginx → waitress → application, and with the S3-01 workload (stack and commands: [TRANSPORT.md](TRANSPORT.md#the-claims-command) for the `claims` command and [TRANSPORT.md](TRANSPORT.md#the-cookies-command) for the `cookies` command; task: [PROGRESS.md](PROGRESS.md#s3-02--compare-mitigations); Sprint 2 limits: [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md); S3-01 workload: [END_TO_END_RESULTS.md](END_TO_END_RESULTS.md)). This document covers S3-02's first two mitigations: smaller claim sets, measured with the `claims` command, and cookie splitting, measured with the `cookies` command. Reference tokens are measured in a later run, which adds its own section here:

- **Smaller claim sets:** covered below.
- **Cookie splitting:** covered below. Splitting a token into `jwt.<index>.<count>` cookies of at most 4,000 characters gets every configuration under Chromium's 4,096-byte cookie limit, but cookie splitting does not get past the limits on the whole token: nginx's 8,192-byte `Cookie` header line, which still carries every chunk, nginx's response buffer for the `Set-Cookie` headers, and Chromium's 180 cookies per domain.
- **Reference tokens:** not covered yet.

## Smaller claim sets

The question: how much does each configuration's token shrink when it carries only essential claims, and does that move any Sprint 2 size limit? The answer from this run:

- **Size:** every token shrinks by the same 641 bytes, from the 22-claim OpenID Connect fixture to its 5 required claims. That is 53.2% of RS256's token, 67.6% of ES256's and EdDSA's, 15.7% of ML-DSA-44's, and only 5.6% and 2.7% of SLH-DSA-SHA2-128s's and SLH-DSA-SHA2-128f's.
- **Limits:** exactly one verdict moves. ML-DSA-44's cookie goes from 4,095 to 3,454 bytes, under Chromium's 4,096-byte cookie name + value limit and under WSL2's nginx response buffer, so the browser that rejected it with OIDC claims now stores and sends it. Nothing moves for Bearer headers or for SLH-DSA, whose header and signature alone exceed every default limit.
- **Latency:** over loopback, the smaller payload saves 0.022–0.025 ms per request for the classical configurations and 0.014 ms for ML-DSA-44 from http.client at concurrency 1, most of it in verification. The SLH-DSA differences, every difference at concurrency 4, and the Chromium differences cannot be told apart from noise and the fixed run order. On a real uplink, the calculated saving is 0.051–5.128 ms per request for every configuration.

Every number below comes from one run on the team's Mac (Apple M5 Pro, 18 cores, macOS 26.5.1, arm64, 16 KiB memory pages; Python 3.15.2, Playwright 1.64.1, Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2 with its default 4 threads), recorded with `make claims` on November 18, 2026 (UTC; just after midnight local time) at commit `df91e2e`, with no uncommitted change to `scripts/` or `fixtures/`. Every token was signed with **ephemeral experiment keys, not production credentials**: each key was generated in memory for the run and discarded, so the tokens in its logs are not credentials either.

| Machine | Run | Files |
| --- | --- | --- |
| Apple M5 Pro (macOS) | [`20261118T053507Z-macos`](results/claims/20261118T053507Z-macos/) | [claims.json](results/claims/20261118T053507Z-macos/claims.json) |

| Phase | Evidence |
| --- | --- |
| Size limits, at the documented defaults | [nginx.conf](results/claims/20261118T053507Z-macos/limits/nginx.conf), [app.log.gz](results/claims/20261118T053507Z-macos/limits/logs/app.log.gz), [browser.log.gz](results/claims/20261118T053507Z-macos/limits/logs/browser.log.gz), [proxy-access.log.gz](results/claims/20261118T053507Z-macos/limits/logs/proxy-access.log.gz), [proxy-error.log.gz](results/claims/20261118T053507Z-macos/limits/logs/proxy-error.log.gz) |
| Latency, OIDC claims | [load.json](results/claims/20261118T053507Z-macos/latency-oidc/load.json), [raw.csv.gz](results/claims/20261118T053507Z-macos/latency-oidc/raw.csv.gz), [logs](results/claims/20261118T053507Z-macos/latency-oidc/logs/), [nginx.conf](results/claims/20261118T053507Z-macos/latency-oidc/nginx.conf) |
| Latency, essential claims | [load.json](results/claims/20261118T053507Z-macos/latency-essential/load.json), [raw.csv.gz](results/claims/20261118T053507Z-macos/latency-essential/raw.csv.gz), [logs](results/claims/20261118T053507Z-macos/latency-essential/logs/), [nginx.conf](results/claims/20261118T053507Z-macos/latency-essential/nginx.conf) |
| Sprint 2 boundaries (WSL2, committed earlier) | [cookie-default/sweep.json](results/transport/20261113T074114Z-wsl2/cookie-default/sweep.json), [cookie-16k/sweep.json](results/transport/20261113T074114Z-wsl2/cookie-16k/sweep.json), [bearer-default/sweep.json](results/transport/20261113T074114Z-wsl2/bearer-default/sweep.json) |

`claims.json` holds the settings, the environment, the claim sets, the token sizes, the derived Sprint 2 verdicts, every size-limit pair with its evidence and nonces, and the latency comparison; each latency directory is exactly what `load --output-dir` writes. The logs are gzip-compressed (`gzip -dc`). `claims.json`, both `load.json` and `raw.csv.gz` files, and every `app.log.gz` and `proxy-access.log.gz` hold no token. The size-limits phase's `browser.log.gz` holds the tokens Chromium sent and received, and its `proxy-error.log.gz` holds nginx's own truncated prefix of each of the four rejected Bearer header lines.

**Machine state.** Nothing else from the project was running: no other stack, load run, or test suite, and the `make serve` stack from the main checkout had been stopped (nothing listened on ports 8080 or 8081). When the run started, 0 sockets were in TIME_WAIT and the 1-minute load average was 2.2 on 18 cores. Spotify and Steam were open. This run replaces a provisional one recorded a few hours earlier, while the other S3-02 candidates' work and an idle `make serve` stack were on the same Mac.

### Claim sets

| Claim set | Fixture | Claims | Payload bytes |
| --- | --- | ---: | ---: |
| `minimal` (Sprint 1, a floor) | [fixtures/claims.json](fixtures/claims.json) | 3 | 63 |
| `oidc` (typical OpenID Connect ID token) | [fixtures/claims_oidc.json](fixtures/claims_oidc.json) | 22 | 618 |
| `essential` | [fixtures/claims_essential.json](fixtures/claims_essential.json) | 5 | 137 |

The essential set keeps `iss` (issuer), `sub` (subject), `aud` (audience), `exp` (expiry), and `iat` (issued at): the five ID Token claims that [OpenID Connect Core 1.0 §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) marks REQUIRED. They are what a relying party needs to validate the token on its own: who issued it, about whom, for which client, and until when. Their values are copied from the `oidc` fixture, so the two payloads differ only in the dropped claims, and payload bytes are the compact JSON that `scripts/token_sizing.payload_bytes` counts.

17 of the oidc fixture's 22 claims were dropped, and the payload goes from 618 to 137 bytes: the authentication context and session (`auth_time`, `nonce`, `acr`, `amr`, `azp`, `sid`), the profile (`name`, `given_name`, `family_name`, `preferred_username`, `email`, `email_verified`, `locale`, `zoneinfo`, `picture`), and the authorization claims (`groups`, `roles`). `nonce` and `auth_time` are required in an ID token only when the authentication request asks for them. An application that needs the dropped claims has to get them from somewhere else, such as the OpenID Connect userinfo endpoint or a server-side session keyed by `sub` or `sid`; that lookup is not measured here.

### Token sizes

Each configuration signed every fixture, unpadded, with a fresh experiment key, and each token was verified (with its own `aud` as the audience) before its size was recorded. Sizes are bytes of the compact token; fixed bytes are the header, the signature, and both dots, which no claim set removes.

| Configuration | Signature bytes | Fixed bytes | Minimal | OIDC | Essential | Shrink (bytes) | Shrink (% of OIDC) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 256 | 380 | 464 | 1,204 | 563 | 641 | 53.2% |
| ES256 | 64 | 124 | 208 | 948 | 307 | 641 | 67.6% |
| EdDSA | 64 | 124 | 208 | 948 | 307 | 641 | 67.6% |
| ML-DSA-44 | 2,420 | 3,271 | 3,355 | 4,095 | 3,454 | 641 | 15.7% |
| SLH-DSA-SHA2-128s | 7,856 | 10,529 | 10,613 | 11,353 | 10,712 | 641 | 5.6% |
| SLH-DSA-SHA2-128f | 17,088 | 22,838 | 22,922 | 23,662 | 23,021 | 641 | 2.7% |

The shrink is the same 641 bytes for every configuration because the header and the signature do not depend on the claims: the header names only `alg` and `typ`, and every signature has a fixed length. Only the base64url payload segment changes, from 824 to 183 characters (token bytes minus fixed bytes) in every row. The relative saving therefore depends only on how much of the token is fixed: two thirds for ES256 and EdDSA, half for RS256, a sixth for ML-DSA-44, and almost nothing for SLH-DSA, whose 7,856- and 17,088-byte signatures dominate. Even the minimal fixture, which is not a realistic claim set, leaves ML-DSA-44 at 3,355 bytes and the SLH-DSA tokens at 10,613 and 22,922.

### Size limits

**Derived from Sprint 2's WSL2 measurements.** These verdicts were not measured by this run: each Sprint 2 boundary is the largest token that verified in that committed WSL2 sweep (the largest `largest_verified_token_bytes` in its `sweep.json`), and each configuration's OIDC and essential token is compared with it. A byte limit does not depend on what the bytes encode, so a token of the same size meets the same limit. Headroom is the boundary minus the token's bytes; a negative headroom means it does not fit.

**cookie-default: 3,915 bytes** (nginx's 4 KiB response buffer on WSL2, which the `Set-Cookie` response header block must fit; [sweep.json](results/transport/20261113T074114Z-wsl2/cookie-default/sweep.json))

| Configuration | OIDC token | OIDC headroom | OIDC fits | Essential token | Essential headroom | Essential fits | Moved |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| RS256 | 1,204 | +2,711 | yes | 563 | +3,352 | yes | no |
| ES256 | 948 | +2,967 | yes | 307 | +3,608 | yes | no |
| EdDSA | 948 | +2,967 | yes | 307 | +3,608 | yes | no |
| ML-DSA-44 | 4,095 | -180 | no | 3,454 | +461 | yes | **yes** |
| SLH-DSA-SHA2-128s | 11,353 | -7,438 | no | 10,712 | -6,797 | no | no |
| SLH-DSA-SHA2-128f | 23,662 | -19,747 | no | 23,021 | -19,106 | no | no |

**cookie-16k: 4,093 bytes** (Chromium's 4,096 bytes of cookie name + value, reached once nginx's buffers are raised to the Mac's 16k; [sweep.json](results/transport/20261113T074114Z-wsl2/cookie-16k/sweep.json))

| Configuration | OIDC token | OIDC headroom | OIDC fits | Essential token | Essential headroom | Essential fits | Moved |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| RS256 | 1,204 | +2,889 | yes | 563 | +3,530 | yes | no |
| ES256 | 948 | +3,145 | yes | 307 | +3,786 | yes | no |
| EdDSA | 948 | +3,145 | yes | 307 | +3,786 | yes | no |
| ML-DSA-44 | 4,095 | -2 | no | 3,454 | +639 | yes | **yes** |
| SLH-DSA-SHA2-128s | 11,353 | -7,260 | no | 10,712 | -6,619 | no | no |
| SLH-DSA-SHA2-128f | 23,662 | -19,569 | no | 23,021 | -18,928 | no | no |

**bearer-default: 8,168 bytes** (nginx's 8,192-byte request header line, `large_client_header_buffers 4 8k`; [sweep.json](results/transport/20261113T074114Z-wsl2/bearer-default/sweep.json))

| Configuration | OIDC token | OIDC headroom | OIDC fits | Essential token | Essential headroom | Essential fits | Moved |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| RS256 | 1,204 | +6,964 | yes | 563 | +7,605 | yes | no |
| ES256 | 948 | +7,220 | yes | 307 | +7,861 | yes | no |
| EdDSA | 948 | +7,220 | yes | 307 | +7,861 | yes | no |
| ML-DSA-44 | 4,095 | +4,073 | yes | 3,454 | +4,714 | yes | no |
| SLH-DSA-SHA2-128s | 11,353 | -3,185 | no | 10,712 | -2,544 | no | no |
| SLH-DSA-SHA2-128f | 23,662 | -15,494 | no | 23,021 | -14,853 | no | no |

**Measured on this Mac at the documented default limits.** One stack with no raised limit (its [nginx.conf](results/claims/20261118T053507Z-macos/limits/nginx.conf) has no `Not a default` line) and headless Chromium sent each configuration's OIDC and essential token once as a `jwt` cookie with production attributes (`Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600`) and once as an `Authorization: Bearer` header, and named the rejecting layer of each rejected pair from every layer's log. Every one of the 24 tokens also verified when sent straight to the application.

| Configuration | Transport | OIDC token | OIDC outcome | Essential token | Essential outcome | Moved |
| --- | --- | ---: | --- | ---: | --- | --- |
| RS256 | cookie | 1,204 | verified | 563 | verified | no |
| RS256 | bearer | 1,204 | verified | 563 | verified | no |
| ES256 | cookie | 948 | verified | 307 | verified | no |
| ES256 | bearer | 948 | verified | 307 | verified | no |
| EdDSA | cookie | 948 | verified | 307 | verified | no |
| EdDSA | bearer | 948 | verified | 307 | verified | no |
| ML-DSA-44 | cookie | 4,095 | rejected by the browser | 3,454 | verified | **yes** |
| ML-DSA-44 | bearer | 4,095 | verified | 3,454 | verified | no |
| SLH-DSA-SHA2-128s | cookie | 11,353 | rejected by the browser | 10,712 | rejected by the browser | no |
| SLH-DSA-SHA2-128s | bearer | 11,353 | rejected by the proxy (400) | 10,712 | rejected by the proxy (400) | no |
| SLH-DSA-SHA2-128f | cookie | 23,662 | rejected by the proxy (502) | 23,021 | rejected by the proxy (502) | no |
| SLH-DSA-SHA2-128f | bearer | 23,662 | rejected by the proxy (400) | 23,021 | rejected by the proxy (400) | no |

- **Rejected by the browser:** Chromium did not store the cookie. With OIDC claims, ML-DSA-44's `Set-Cookie` was 4,156 bytes and its name + value 4,098 bytes, 2 over Chromium's limit; `BrowserContext.cookies()` listed no `jwt` cookie afterwards. SLH-DSA-SHA2-128s's name + value was 11,356 bytes with OIDC claims and 10,715 with essential claims.
- **Rejected by the proxy (502):** SLH-DSA-SHA2-128f's `Set-Cookie` response did not fit nginx's 16 KiB response buffer: the application answered 200, and nginx logged `upstream sent too big header` and returned 502 for the issue request.
- **Rejected by the proxy (400):** both SLH-DSA Bearer headers are longer than nginx's 8,192-byte header line: nginx logged `client sent too long header line` and answered 400, and the verify request never reached the application.

**What moved.** Only ML-DSA-44's cookie: it was rejected by the browser with OIDC claims and verified with the essential claims, and the derived verdicts agree (it moves at both cookie-default and cookie-16k, from -180 and -2 bytes of headroom to +461 and +639). The Mac's measured cookie verdicts match cookie-16k's derived ones, as expected, because cookie-16k raised WSL2's nginx buffers to the Mac's default 16k. Nothing moved for Bearer: the classical and ML-DSA-44 tokens already fit with OIDC claims, and the SLH-DSA ones still do not. Nothing moved for SLH-DSA on either transport: its fixed bytes alone, 10,529 and 22,838, exceed every default limit a token has to pass (Chromium's 4,096 bytes of cookie name + value, nginx's 8,192-byte header line, and the Sprint 2 boundaries of 3,915, 4,093, and 8,168 bytes), so no claim set can make an SLH-DSA token fit.

### Latency

The S3-01 workload ([END_TO_END_RESULTS.md](END_TO_END_RESULTS.md#workload)) ran twice, first with OIDC claims and then with the essential claims, each on a new stack: a closed loop of `GET /api/token/verify?timing=1&nonce=<32 hex digits>` requests with the token in an `Authorization: Bearer` header, from http.client threads and from Chromium's test page, at concurrency 1 and 4, with 1 second of warm-up and 2 seconds measured per cell, `--header-buffers 32k`, and `--upstream-keepalive 64`. Size-control cells were off: they answer a different question. Every measured request verified: 172,110 with OIDC claims and 187,375 with essential claims, none failed, and every cell had at least 2,209 verified requests.

Latency is the client-measured time from sending a request to reading its whole response body, in milliseconds; p95 is nearest-rank. The difference is the essential mean minus the OIDC mean, so a negative difference means the essential claims were faster. Chromium coarsens its timer to about 0.1 ms, so its medians and p95 values are multiples of 0.1 ms.

**http.client (direct), concurrency 1**

| Configuration | OIDC token | Essential token | OIDC mean | Essential mean | Difference | OIDC median | Essential median | OIDC p95 | Essential p95 | OIDC req/s | Essential req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 563 | 0.205 | 0.180 | -0.025 | 0.203 | 0.178 | 0.222 | 0.194 | 4,857 | 5,537 |
| ES256 | 948 | 307 | 0.218 | 0.193 | -0.024 | 0.215 | 0.193 | 0.236 | 0.206 | 4,573 | 5,147 |
| EdDSA | 948 | 307 | 0.214 | 0.193 | -0.022 | 0.212 | 0.192 | 0.229 | 0.204 | 4,649 | 5,166 |
| ML-DSA-44 | 4,095 | 3,454 | 0.230 | 0.215 | -0.014 | 0.229 | 0.215 | 0.246 | 0.228 | 4,334 | 4,625 |
| SLH-DSA-SHA2-128s | 11,353 | 10,712 | 0.402 | 0.395 | -0.007 | 0.399 | 0.394 | 0.428 | 0.409 | 2,482 | 2,524 |
| SLH-DSA-SHA2-128f | 23,662 | 23,021 | 0.703 | 0.683 | -0.019 | 0.697 | 0.682 | 0.734 | 0.699 | 1,421 | 1,461 |

**http.client (direct), concurrency 4**

| Configuration | OIDC token | Essential token | OIDC mean | Essential mean | Difference | OIDC median | Essential median | OIDC p95 | Essential p95 | OIDC req/s | Essential req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 563 | 0.651 | 0.559 | -0.092 | 0.627 | 0.535 | 0.971 | 0.837 | 6,134 | 7,145 |
| ES256 | 948 | 307 | 0.630 | 0.554 | -0.075 | 0.608 | 0.525 | 0.918 | 0.840 | 6,340 | 7,200 |
| EdDSA | 948 | 307 | 0.625 | 0.529 | -0.096 | 0.604 | 0.507 | 0.917 | 0.781 | 6,388 | 7,552 |
| ML-DSA-44 | 4,095 | 3,454 | 0.568 | 0.547 | -0.022 | 0.546 | 0.507 | 0.834 | 0.846 | 7,022 | 7,301 |
| SLH-DSA-SHA2-128s | 11,353 | 10,712 | 1.136 | 1.031 | -0.105 | 1.114 | 1.003 | 1.636 | 1.502 | 3,515 | 3,875 |
| SLH-DSA-SHA2-128f | 23,662 | 23,021 | 2.107 | 2.063 | -0.044 | 2.084 | 2.043 | 3.030 | 2.969 | 1,896 | 1,936 |

**Chromium (browser), concurrency 1**

| Configuration | OIDC token | Essential token | OIDC mean | Essential mean | Difference | OIDC median | Essential median | OIDC p95 | Essential p95 | OIDC req/s | Essential req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 563 | 0.462 | 0.422 | -0.041 | 0.400 | 0.400 | 0.500 | 0.500 | 2,162 | 2,370 |
| ES256 | 948 | 307 | 0.489 | 0.401 | -0.087 | 0.500 | 0.400 | 0.600 | 0.500 | 2,045 | 2,490 |
| EdDSA | 948 | 307 | 0.453 | 0.396 | -0.057 | 0.400 | 0.400 | 0.500 | 0.500 | 2,208 | 2,524 |
| ML-DSA-44 | 4,095 | 3,454 | 0.488 | 0.472 | -0.016 | 0.500 | 0.500 | 0.600 | 0.500 | 2,048 | 2,118 |
| SLH-DSA-SHA2-128s | 11,353 | 10,712 | 0.622 | 0.612 | -0.010 | 0.600 | 0.600 | 0.700 | 0.700 | 1,607 | 1,633 |
| SLH-DSA-SHA2-128f | 23,662 | 23,021 | 0.905 | 0.892 | -0.013 | 0.900 | 0.900 | 1.000 | 1.000 | 1,104 | 1,120 |

**Chromium (browser), concurrency 4**

| Configuration | OIDC token | Essential token | OIDC mean | Essential mean | Difference | OIDC median | Essential median | OIDC p95 | Essential p95 | OIDC req/s | Essential req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 563 | 0.973 | 0.916 | -0.057 | 0.900 | 0.800 | 1.300 | 1.200 | 4,110 | 4,366 |
| ES256 | 948 | 307 | 0.977 | 0.905 | -0.072 | 0.900 | 0.800 | 1.300 | 1.200 | 4,094 | 4,419 |
| EdDSA | 948 | 307 | 0.955 | 0.905 | -0.050 | 0.900 | 0.800 | 1.300 | 1.200 | 4,186 | 4,419 |
| ML-DSA-44 | 4,095 | 3,454 | 0.917 | 0.916 | -0.000 | 0.800 | 0.800 | 1.200 | 1.200 | 4,362 | 4,364 |
| SLH-DSA-SHA2-128s | 11,353 | 10,712 | 1.428 | 1.485 | +0.057 | 1.300 | 1.400 | 2.000 | 2.100 | 2,799 | 2,691 |
| SLH-DSA-SHA2-128f | 23,662 | 23,021 | 2.418 | 2.565 | +0.147 | 2.400 | 2.500 | 3.500 | 3.900 | 1,653 | 1,558 |

**Noise level.** EdDSA and ES256 tokens are the same size in both runs, so the difference between their means shows how much two cells differ without any change in size. From http.client at concurrency 1 it is -0.004 ms with OIDC claims and -0.001 ms with essential claims; at concurrency 4, -0.005 and -0.026 ms. From Chromium it is -0.036 and -0.006 ms at concurrency 1, and -0.022 and -0.000 ms at concurrency 4. This measures noise within one run only; the two runs ran one after the other, always OIDC first, so a drift between them would affect every configuration's difference alike and does not show here.

Where the saving is clear, http.client at concurrency 1, the components show where it comes from (difference of each component's mean, essential minus OIDC, in ms):

| Configuration | Total | Transfer | Other handling | Verification |
| --- | ---: | ---: | ---: | ---: |
| RS256 | -0.025 | -0.009 | -0.003 | -0.013 |
| ES256 | -0.024 | -0.007 | -0.003 | -0.014 |
| EdDSA | -0.022 | -0.005 | -0.003 | -0.013 |
| ML-DSA-44 | -0.014 | -0.005 | -0.003 | -0.006 |
| SLH-DSA-SHA2-128s | -0.007 | -0.007 | -0.003 | +0.004 |
| SLH-DSA-SHA2-128f | -0.019 | -0.009 | -0.004 | -0.006 |

- **http.client, concurrency 1:** RS256, ES256, and EdDSA are 0.022–0.025 ms faster with the essential claims, more than five times the 0.001–0.004 ms noise, and their throughput rises accordingly (ES256: 4,573 to 5,147 req/s). Over half of it is verification (0.013–0.014 ms): `verify_token` decodes and parses a smaller payload and checks fewer claims. Transfer of the 641 fewer bytes through both connections saves 0.005–0.009 ms and other handling 0.003 ms. ML-DSA-44 saves 0.014 ms. The saving follows the share of the token that was removed, largest for the classical tokens and smaller for ML-DSA-44. SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f are 0.007 and 0.019 ms faster, although 641 bytes are only 5.6% and 2.7% of their tokens; SLH-DSA-SHA2-128f's difference is larger than that share suggests, so part of it may come from the run order rather than the claims.
- **http.client, concurrency 4:** every configuration was faster with the essential claims: the classical configurations by 0.075–0.096 ms, ML-DSA-44 by 0.022 ms, and SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f by 0.105 and 0.044 ms, against same-size noise of 0.005–0.026 ms. These differences do not follow the share of the token that was removed: SLH-DSA-SHA2-128s, whose token shrank by 5.6%, gained more than ES256, whose token shrank by 67.6%. Because the OIDC run always ran first, a drift between the two runs cannot be separated from an effect of size here, so these differences are reported as measured and not attributed to the claims.
- **Chromium:** at concurrency 1, every configuration was 0.010–0.087 ms faster with the essential claims, against same-size noise of up to 0.036 ms and a timer coarsened to about 0.1 ms; at concurrency 4 the differences range from -0.072 to +0.147 ms, with both signs. No consistent effect is measurable from the browser.

**Modeled network saving (calculated, not measured).** Loopback makes transfer nearly free. From each run's `network_model`, the modeled upload time of the direct client's request on a new or idle TCP connection (the S3-01 model: bytes at the uplink rate plus one round trip per extra slow-start round, with an initial window of 14,600 bytes) saves, at each illustrative profile:

| Configuration | OIDC request bytes | Essential request bytes | Saved bytes | 100 Mbit/s, 10 ms RTT | 10 Mbit/s, 50 ms RTT | 1 Mbit/s, 100 ms RTT |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,360 | 719 | 641 | 0.051 | 0.513 | 5.128 |
| ES256 | 1,104 | 463 | 641 | 0.051 | 0.513 | 5.128 |
| EdDSA | 1,104 | 463 | 641 | 0.051 | 0.513 | 5.128 |
| ML-DSA-44 | 4,251 | 3,610 | 641 | 0.051 | 0.513 | 5.128 |
| SLH-DSA-SHA2-128s | 11,509 | 10,868 | 641 | 0.051 | 0.513 | 5.128 |
| SLH-DSA-SHA2-128f | 23,818 | 23,177 | 641 | 0.051 | 0.513 | 5.128 |

The saved milliseconds are the same for every configuration, because no request crosses a slow-start round: SLH-DSA-SHA2-128f's request needs two rounds with either claim set, and every other request fits in the first. So the 641 bytes save only serialization time, 0.051–5.128 ms per request, which is more than every measured loopback difference on the two slower profiles.

### Reproduce

From a clean checkout with the environment from [TRANSPORT.md](TRANSPORT.md#setup), with `TRANSPORT_ENV` set, `TMPDIR` unset (so the stacks' run directories land in `/tmp`), and no other load on the machine:

```bash
make claims
# the same command, which make claims runs with --output-dir results/claims/<UTC time>-<platform>:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py claims --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir results/claims/<YYYYMMDDTHHMMSSZ>-macos
# the same settings, from this run's claims.json:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py claims --settings results/claims/20261118T053507Z-macos/claims.json --output-dir results/claims/<YYYYMMDDTHHMMSSZ>-macos
# one latency run alone, from its saved load.json:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --settings results/claims/20261118T053507Z-macos/latency-essential/load.json --output-dir /tmp/latency-essential
```

The run took under 3 minutes. `--output-dir` must not exist yet or be empty. [TRANSPORT.md](TRANSPORT.md#the-claims-command) describes every option and output file. The tables above come from `claims.json`, and each latency cell's numbers can be recomputed from its rows in the `raw.csv.gz` files.

The recorded run's printed output, one line per configuration for each phase: its token sizes, its derived headroom at each Sprint 2 boundary, its measured outcomes at the defaults, and its latency with OIDC and then essential claims (mean, difference, median, p95, and throughput):

```text
size     RS256              minimal    464 B  oidc  1,204 B  essential    563 B  saves 641 B (53.2% of oidc)
size     ES256              minimal    208 B  oidc    948 B  essential    307 B  saves 641 B (67.6% of oidc)
size     EdDSA              minimal    208 B  oidc    948 B  essential    307 B  saves 641 B (67.6% of oidc)
size     ML-DSA-44          minimal  3,355 B  oidc  4,095 B  essential  3,454 B  saves 641 B (15.7% of oidc)
size     SLH-DSA-SHA2-128s  minimal 10,613 B  oidc 11,353 B  essential 10,712 B  saves 641 B (5.6% of oidc)
size     SLH-DSA-SHA2-128f  minimal 22,922 B  oidc 23,662 B  essential 23,021 B  saves 641 B (2.7% of oidc)
sprint2  cookie-default 3,915 B  RS256              oidc  +2,711 B fits  essential  +3,352 B fits
sprint2  cookie-default 3,915 B  ES256              oidc  +2,967 B fits  essential  +3,608 B fits
sprint2  cookie-default 3,915 B  EdDSA              oidc  +2,967 B fits  essential  +3,608 B fits
sprint2  cookie-default 3,915 B  ML-DSA-44          oidc    -180 B over  essential    +461 B fits  moved
sprint2  cookie-default 3,915 B  SLH-DSA-SHA2-128s  oidc  -7,438 B over  essential  -6,797 B over
sprint2  cookie-default 3,915 B  SLH-DSA-SHA2-128f  oidc -19,747 B over  essential -19,106 B over
sprint2  cookie-16k 4,093 B      RS256              oidc  +2,889 B fits  essential  +3,530 B fits
sprint2  cookie-16k 4,093 B      ES256              oidc  +3,145 B fits  essential  +3,786 B fits
sprint2  cookie-16k 4,093 B      EdDSA              oidc  +3,145 B fits  essential  +3,786 B fits
sprint2  cookie-16k 4,093 B      ML-DSA-44          oidc      -2 B over  essential    +639 B fits  moved
sprint2  cookie-16k 4,093 B      SLH-DSA-SHA2-128s  oidc  -7,260 B over  essential  -6,619 B over
sprint2  cookie-16k 4,093 B      SLH-DSA-SHA2-128f  oidc -19,569 B over  essential -18,928 B over
sprint2  bearer-default 8,168 B  RS256              oidc  +6,964 B fits  essential  +7,605 B fits
sprint2  bearer-default 8,168 B  ES256              oidc  +7,220 B fits  essential  +7,861 B fits
sprint2  bearer-default 8,168 B  EdDSA              oidc  +7,220 B fits  essential  +7,861 B fits
sprint2  bearer-default 8,168 B  ML-DSA-44          oidc  +4,073 B fits  essential  +4,714 B fits
sprint2  bearer-default 8,168 B  SLH-DSA-SHA2-128s  oidc  -3,185 B over  essential  -2,544 B over
sprint2  bearer-default 8,168 B  SLH-DSA-SHA2-128f  oidc -15,494 B over  essential -14,853 B over
limits   cookie RS256              oidc  1,204 B verified                essential    563 B verified
limits   bearer RS256              oidc  1,204 B verified                essential    563 B verified
limits   cookie ES256              oidc    948 B verified                essential    307 B verified
limits   bearer ES256              oidc    948 B verified                essential    307 B verified
limits   cookie EdDSA              oidc    948 B verified                essential    307 B verified
limits   bearer EdDSA              oidc    948 B verified                essential    307 B verified
limits   cookie ML-DSA-44          oidc  4,095 B rejected by browser     essential  3,454 B verified  moved
limits   bearer ML-DSA-44          oidc  4,095 B verified                essential  3,454 B verified
limits   cookie SLH-DSA-SHA2-128s  oidc 11,353 B rejected by browser     essential 10,712 B rejected by browser
limits   bearer SLH-DSA-SHA2-128s  oidc 11,353 B rejected by proxy       essential 10,712 B rejected by proxy
limits   cookie SLH-DSA-SHA2-128f  oidc 23,662 B rejected by proxy       essential 23,021 B rejected by proxy
limits   bearer SLH-DSA-SHA2-128f  oidc 23,662 B rejected by proxy       essential 23,021 B rejected by proxy
latency  direct  c=1   RS256               1,204 ->    563 B  mean 0.205 -> 0.180 ms (-0.025)  median 0.203 -> 0.178  p95 0.222 -> 0.194  4,856.8 -> 5,537.3 req/s
latency  direct  c=1   ES256                 948 ->    307 B  mean 0.218 -> 0.193 ms (-0.024)  median 0.215 -> 0.193  p95 0.236 -> 0.206  4,572.9 -> 5,147.2 req/s
latency  direct  c=1   EdDSA                 948 ->    307 B  mean 0.214 -> 0.193 ms (-0.022)  median 0.212 -> 0.192  p95 0.229 -> 0.204  4,649.3 -> 5,165.6 req/s
latency  direct  c=1   ML-DSA-44           4,095 ->  3,454 B  mean 0.230 -> 0.215 ms (-0.014)  median 0.229 -> 0.215  p95 0.246 -> 0.228  4,334.3 -> 4,625.0 req/s
latency  direct  c=1   SLH-DSA-SHA2-128s  11,353 -> 10,712 B  mean 0.402 -> 0.395 ms (-0.007)  median 0.399 -> 0.394  p95 0.428 -> 0.409  2,482.0 -> 2,524.1 req/s
latency  direct  c=1   SLH-DSA-SHA2-128f  23,662 -> 23,021 B  mean 0.703 -> 0.683 ms (-0.019)  median 0.697 -> 0.682  p95 0.734 -> 0.699  1,420.9 -> 1,461.2 req/s
latency  direct  c=4   RS256               1,204 ->    563 B  mean 0.651 -> 0.559 ms (-0.092)  median 0.627 -> 0.535  p95 0.971 -> 0.837  6,134.3 -> 7,144.9 req/s
latency  direct  c=4   ES256                 948 ->    307 B  mean 0.630 -> 0.554 ms (-0.075)  median 0.608 -> 0.525  p95 0.918 -> 0.840  6,340.0 -> 7,199.9 req/s
latency  direct  c=4   EdDSA                 948 ->    307 B  mean 0.625 -> 0.529 ms (-0.096)  median 0.604 -> 0.507  p95 0.917 -> 0.781  6,388.0 -> 7,552.0 req/s
latency  direct  c=4   ML-DSA-44           4,095 ->  3,454 B  mean 0.568 -> 0.547 ms (-0.022)  median 0.546 -> 0.507  p95 0.834 -> 0.846  7,021.7 -> 7,300.6 req/s
latency  direct  c=4   SLH-DSA-SHA2-128s  11,353 -> 10,712 B  mean 1.136 -> 1.031 ms (-0.105)  median 1.114 -> 1.003  p95 1.636 -> 1.502  3,514.7 -> 3,875.4 req/s
latency  direct  c=4   SLH-DSA-SHA2-128f  23,662 -> 23,021 B  mean 2.107 -> 2.063 ms (-0.044)  median 2.084 -> 2.043  p95 3.030 -> 2.969  1,895.7 -> 1,936.0 req/s
latency  browser c=1   RS256               1,204 ->    563 B  mean 0.462 -> 0.422 ms (-0.041)  median 0.400 -> 0.400  p95 0.500 -> 0.500  2,161.8 -> 2,370.3 req/s
latency  browser c=1   ES256                 948 ->    307 B  mean 0.489 -> 0.401 ms (-0.087)  median 0.500 -> 0.400  p95 0.600 -> 0.500  2,045.4 -> 2,490.3 req/s
latency  browser c=1   EdDSA                 948 ->    307 B  mean 0.453 -> 0.396 ms (-0.057)  median 0.400 -> 0.400  p95 0.500 -> 0.500  2,208.4 -> 2,524.2 req/s
latency  browser c=1   ML-DSA-44           4,095 ->  3,454 B  mean 0.488 -> 0.472 ms (-0.016)  median 0.500 -> 0.500  p95 0.600 -> 0.500  2,047.9 -> 2,117.7 req/s
latency  browser c=1   SLH-DSA-SHA2-128s  11,353 -> 10,712 B  mean 0.622 -> 0.612 ms (-0.010)  median 0.600 -> 0.600  p95 0.700 -> 0.700  1,607.3 -> 1,633.0 req/s
latency  browser c=1   SLH-DSA-SHA2-128f  23,662 -> 23,021 B  mean 0.905 -> 0.892 ms (-0.013)  median 0.900 -> 0.900  p95 1.000 -> 1.000  1,104.2 -> 1,120.4 req/s
latency  browser c=4   RS256               1,204 ->    563 B  mean 0.973 -> 0.916 ms (-0.057)  median 0.900 -> 0.800  p95 1.300 -> 1.200  4,110.3 -> 4,366.4 req/s
latency  browser c=4   ES256                 948 ->    307 B  mean 0.977 -> 0.905 ms (-0.072)  median 0.900 -> 0.800  p95 1.300 -> 1.200  4,093.6 -> 4,418.7 req/s
latency  browser c=4   EdDSA                 948 ->    307 B  mean 0.955 -> 0.905 ms (-0.050)  median 0.900 -> 0.800  p95 1.300 -> 1.200  4,186.0 -> 4,419.1 req/s
latency  browser c=4   ML-DSA-44           4,095 ->  3,454 B  mean 0.917 -> 0.916 ms (-0.000)  median 0.800 -> 0.800  p95 1.200 -> 1.200  4,362.2 -> 4,364.5 req/s
latency  browser c=4   SLH-DSA-SHA2-128s  11,353 -> 10,712 B  mean 1.428 -> 1.485 ms (+0.057)  median 1.300 -> 1.400  p95 2.000 -> 2.100  2,799.2 -> 2,691.4 req/s
latency  browser c=4   SLH-DSA-SHA2-128f  23,662 -> 23,021 B  mean 2.418 -> 2.565 ms (+0.147)  median 2.400 -> 2.500  p95 3.500 -> 3.900  1,652.7 -> 1,557.5 req/s
Saved the results to results/claims/20261118T053507Z-macos
```

### Limitations

- **WSL2 has not been run yet.** The `claims` command has not been run on WSL2; the derived verdicts come from Sprint 2's WSL2 sweeps, but the measured size limits and latency are from this Mac only. On WSL2 the measured cookie verdicts should follow cookie-default, where nginx's 4 KiB buffer is the first limit.
- **Loopback only.** Both latency runs ran over loopback on one machine; the network saving is only calculated.
- **One run per claim set, in a fixed order.** Each claim set ran once, the OIDC run first, so run-to-run variation was not measured, and a drift between the two runs cannot be told apart from an effect of size. Within each run, EdDSA's difference from ES256 shows the noise level. For this reason the concurrency-4 differences are reported but not attributed to the claims.
- **Illustrative fixture values.** The fixture's values (an `example.test` issuer, a made-up subject, a name and an email address) are illustrative. The 641-byte saving is the size of the dropped claims' values; a real provider's claims could be larger or smaller.
- **The essential set is a team assumption.** It is OpenID Connect's five required ID Token claims; other plausible sets, such as RFC 9068's access-token claims (adding `client_id` and `jti`) or keeping `roles` for authorization, were not measured. Changing the fixture file and rerunning `make claims` would measure one.
- **The dropped claims' cost is not measured.** Getting them from the userinfo endpoint or a server-side session adds a lookup that a self-contained token avoids.
- **Tokens in two logs.** nginx's error log in `limits/` holds a truncated prefix of each rejected Bearer header line (`client sent too long header line`), as Sprint 2's logs do, and `browser.log.gz` in `limits/` holds the tokens the browser handled; all were signed with discarded experiment keys.
- **Not the default limits for latency.** The latency stacks use `--header-buffers 32k` and the non-default `--upstream-keepalive 64`, as S3-01 did; the size-limits stack keeps every default.
- **Derived cookie verdicts use the default attributes.** The Sprint 2 cookie sweeps used `Path=/; HttpOnly; SameSite=Strict`, so their `Set-Cookie` lines were 22 bytes shorter than with the production attributes used here. That matters only at cookie-default, where nginx counts the whole response header block, and changes no verdict: the smallest headroom of a token that fits there is ML-DSA-44's +461 bytes.
- **One browser, one size per pair, HTTP/1.1 without TLS.** Only Chromium was used, each size-limit pair was sent once at the fixture's size (not swept), and HTTPS and HTTP/2 are S3-04's work.
- **Machine state.** Nothing else from the project was running, but Spotify and Steam were open. The 1-minute load average was 2.2 when the run started and 4.7 when it ended, including the run's own load.

## Cookie splitting

The question: if the application issues an oversized token as several cookies and reassembles them, which limits does the token still run into, how does the application handle chunks that are missing, reordered, or mixed up, and what does splitting cost in latency? The answer from this run:

- **Per-cookie limit:** cookie splitting gets every configuration under Chromium's 4,096 bytes of cookie name + value. Split into chunks of at most 4,000 characters, the largest chunk's name + value is 2,055 bytes for ML-DSA-44, 3,792 for SLH-DSA-SHA2-128s, and 3,951 for SLH-DSA-SHA2-128f (calculated), and Chromium stored every chunk wherever nginx let the issue response through. The per-cookie probe measured the limit itself: a 4,096-byte chunk was stored and a 4,097-byte one was not.
- **What it does not get past:** the limits on the whole token. Every chunk travels in one `Cookie` header line, so nginx's 8,192-byte line still rejects SLH-DSA-SHA2-128s (an 11,391-byte split line, 400), and every chunk's `Set-Cookie` header has to fit in nginx's 16 KiB response buffer, which SLH-DSA-SHA2-128f's 24,263-byte issue response does not (502). At the documented defaults only ML-DSA-44 moves, from rejected by the browser to verified; the largest split ML-DSA-44 token that got through was 8,154 bytes, whose `Cookie` line is exactly 8,192 bytes. With nginx's header and response buffers raised to 32k, every split pair verified, while Chromium still refused every post-quantum single cookie.
- **Cookie count:** 180 chunk cookies were stored and verified; with 181, Chromium kept only 150, so a split token and the site's other cookies together cannot exceed 180 cookies per domain.
- **Missing and reordered chunks:** reversed, rotated, and interleaved chunks verified. A missing chunk got 401 and a repeated chunk, a chunk from another split, or an index out of range got 400, all before any verification; a chunk from another token got 401 from the signature check; chunks together with a `jwt` cookie or a Bearer header got 400. Chromium sent the chunks in index order in every split pair.
- **Latency:** over loopback from http.client at concurrency 1, splitting cost 0.001 ms per request for ML-DSA-44, 0.017 ms for SLH-DSA-SHA2-128s, and 0.054 ms for SLH-DSA-SHA2-128f, against same-size noise of 0.001 ms; the application's own handling grew with the number of chunks, by 0.006–0.013 ms for 2–6 chunks, and the classical tokens, in one chunk, were 0.004–0.006 ms faster, which is drift between the two runs. The larger differences at concurrency 4 are not attributed to splitting (see [Latency](#latency-1)). From Chromium only the classical tokens can be compared, because Chromium refuses every post-quantum single cookie, while split it delivered all six. The calculated network cost is 4–54 more request bytes, at most 0.432 ms on a 1 Mbit/s uplink.

Every number below comes from one run on the team's Mac (Apple M5 Pro, 18 cores, macOS 26.5.1, arm64, 16 KiB memory pages; Python 3.15.2, Playwright 1.64.1, Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2 with its default 4 threads), recorded with `make cookies` on November 18, 2026 (UTC, 10:57–11:00; just before 6 a.m. local time) at commit `440075e`, with no uncommitted change to `scripts/` or `fixtures/`. Every token was signed with **ephemeral experiment keys, not production credentials**: each key was generated in memory by the run's applications and discarded, so the tokens and chunks in its browser logs are not credentials either. Calculated figures are labeled as such; everything else was measured.

| Machine | Run | Files |
| --- | --- | --- |
| Apple M5 Pro (macOS) | [`20261118T105758Z-macos`](results/cookies/20261118T105758Z-macos/) | [cookies.json](results/cookies/20261118T105758Z-macos/cookies.json) |

| Phase | Evidence |
| --- | --- |
| Size limits and boundary, at the documented defaults | [nginx.conf](results/cookies/20261118T105758Z-macos/limits-default/nginx.conf), [app.log.gz](results/cookies/20261118T105758Z-macos/limits-default/logs/app.log.gz), [browser.log.gz](results/cookies/20261118T105758Z-macos/limits-default/logs/browser.log.gz), [proxy-access.log.gz](results/cookies/20261118T105758Z-macos/limits-default/logs/proxy-access.log.gz), [proxy-error.log.gz](results/cookies/20261118T105758Z-macos/limits-default/logs/proxy-error.log.gz) |
| Size limits, probes, and chunk handling, with raised buffers | [nginx.conf](results/cookies/20261118T105758Z-macos/limits-raised/nginx.conf), [app.log.gz](results/cookies/20261118T105758Z-macos/limits-raised/logs/app.log.gz), [browser.log.gz](results/cookies/20261118T105758Z-macos/limits-raised/logs/browser.log.gz), [proxy-access.log.gz](results/cookies/20261118T105758Z-macos/limits-raised/logs/proxy-access.log.gz), [proxy-error.log.gz](results/cookies/20261118T105758Z-macos/limits-raised/logs/proxy-error.log.gz) |
| Latency, one `jwt` cookie | [load.json](results/cookies/20261118T105758Z-macos/latency-cookie/load.json), [raw.csv.gz](results/cookies/20261118T105758Z-macos/latency-cookie/raw.csv.gz), [logs](results/cookies/20261118T105758Z-macos/latency-cookie/logs/), [nginx.conf](results/cookies/20261118T105758Z-macos/latency-cookie/nginx.conf) |
| Latency, split cookies | [load.json](results/cookies/20261118T105758Z-macos/latency-split/load.json), [raw.csv.gz](results/cookies/20261118T105758Z-macos/latency-split/raw.csv.gz), [logs](results/cookies/20261118T105758Z-macos/latency-split/logs/), [nginx.conf](results/cookies/20261118T105758Z-macos/latency-split/nginx.conf) |

`cookies.json` holds the settings, the environment, the chunk format and plan, every size-limit pair, boundary probe, and probe with its bytes, evidence, and nonces, the chunk-handling cases, and the latency comparison; each latency directory is exactly what `load --output-dir` writes. The logs are gzip-compressed (`gzip -dc`). `cookies.json`, both `load.json` and `raw.csv.gz` files, and every `app.log.gz` and `proxy-access.log.gz` hold no token, chunk, or cookie value. The two size-limit phases' `browser.log.gz` files hold the tokens and chunks Chromium sent, received, and stored, and `limits-default/logs/proxy-error.log.gz` holds nginx's own truncated prefix of each rejected `Cookie` line.

**Machine state.** The other S3-02 candidates were being built and tested on the same Mac and share its CPU and ephemeral ports. When the run started (10:57:58 UTC), none of their stacks, load runs, or test suites was running (no other nginx, application, or test process), 185 sockets were in TIME_WAIT, and the 1-minute load average was 3.0 on 18 cores; the `make serve` stack from the main checkout was not running (nothing listened on ports 8080 or 8081 a minute before). Another candidate's full test suite started about 7 seconds before the run ended, during the split latency run's last Chromium cells, and the load average was 3.3 at the end, including the run's own load. This is one candidate's run; the run of the implementation that is kept is to be recorded again on an idle Mac.

### Format

The application ([scripts/transport_app.py](scripts/transport_app.py), [Token endpoints](TRANSPORT.md#token-endpoints)) issues a split with `GET /api/token/issue?alg=<name>&delivery=split`, one `Set-Cookie` header per chunk:

| Property | Value |
| --- | --- |
| Cookie names | `jwt.<index>.<count>`, for example `jwt.0.3`, `jwt.1.3`, `jwt.2.3`; each number is `0` or has no leading zero and at most 7 digits |
| Chunk sizes | near-equal: with `n` chunks, the first `token_bytes % n` have one character more |
| Default count | `max(1, ceil(token_bytes / 4000))`, so no chunk is longer than 4,000 characters; `chunks=<n>` (1 to 1,000) chooses another |
| Attributes | every chunk gets the same attributes; the size-limit pairs and probes use the production set `Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600` |
| Chromium's count limit | 180 cookies per domain (`kDomainMaxCookies`, a code constant; see [TRANSPORT.md](TRANSPORT.md#the-cookies-command)) |
| Verify source | `split`: the chunks are joined in index order, whatever order they arrive in, and verified like any other token |

Every name carries the count, so an incomplete set is refused with the missing indices named, before anything is verified, as ASP.NET Core's chunked cookies record their count. The dots keep the names apart from `jwt_old`, `jwt2`, `jwtx`, and the other names the application already ignores, and a single `jwt` cookie keeps its old meaning. A token of 4,000 bytes or less still uses the format, as the single chunk `jwt.0.1`. The application's statuses: 401 for an incomplete set, because the token is effectively absent; 400 for an ambiguous one (a repeated index, chunks naming different counts, an index out of range), as for two `jwt` cookies; and 400 `more than one token` for chunk cookies sent with a `jwt` cookie or a Bearer header.

### Chunk plan

**Calculated, not measured.** Each configuration's unpadded OIDC token (`token_sizing.token_bytes`), split at the default count, with the bytes each limit counts: a cookie's name + value (Chromium's 4,096 bytes), the `Set-Cookie` lines with production attributes (which, with the status line and the other response headers, must fit in nginx's `proxy_buffer_size`), and the `Cookie` line the client sends (nginx's 8,192-byte header line). The split `Cookie` line is every `name=value` joined with `"; "`.

| Configuration | Token | Chunks | Chunk sizes | Cookie name + value | Largest chunk name + value | Cookie line | Split Cookie line | Set-Cookie lines (cookie) | Set-Cookie lines (split) |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 1,204 | 1,207 | 1,211 | 1,218 | 1,222 | 1,279 | 1,283 |
| ES256 | 948 | 1 | 948 | 951 | 955 | 962 | 966 | 1,023 | 1,027 |
| EdDSA | 948 | 1 | 948 | 951 | 955 | 962 | 966 | 1,023 | 1,027 |
| ML-DSA-44 | 4,095 | 2 | 2,048, 2,047 | 4,098 | 2,055 | 4,109 | 4,123 | 4,170 | 4,253 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | 3,785, 3,784, 3,784 | 11,356 | 3,792 | 11,367 | 11,391 | 11,428 | 11,590 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | 3,944, 3,944, 3,944, 3,944, 3,943, 3,943 | 23,665 | 3,951 | 23,676 | 23,730 | 23,737 | 24,136 |

Against the documented limits (calculated): every split fits Chromium's per-cookie limit and its 180 cookies, while the single cookie of ML-DSA-44 and both SLH-DSA tokens does not fit the per-cookie limit. Splitting does not shorten the `Cookie` line, it lengthens it by each name and separator (4 bytes for one chunk, 14 for two, 24 for three, 54 for six), so both SLH-DSA tokens are over nginx's 8,192-byte line either way. The `Set-Cookie` lines grow by each chunk's name and attributes, to 24,136 bytes for SLH-DSA-SHA2-128f.

### Size limits

**Measured on this Mac.** Each stack sent each configuration's OIDC token once as a single `jwt` cookie and once split at the default count, both with production attributes, from a new Chromium context through nginx to the application, and named the rejecting layer of each rejected pair from every layer's log (issue, then cookie jar, then verify). Every one of the 24 tokens also verified when its cookie or chunks were sent straight to the application.

**At the documented defaults** (stack `limits-default`; its [nginx.conf](results/cookies/20261118T105758Z-macos/limits-default/nginx.conf) has no `Not a default` line: `large_client_header_buffers 4 8k`, and a 16 KiB `proxy_buffer_size`, one memory page):

| Configuration | Token | Single cookie | Chunks | Chunks stored | Split cookies | Moved |
| --- | ---: | --- | ---: | ---: | --- | --- |
| RS256 | 1,204 | verified | 1 | 1 of 1 | verified | no |
| ES256 | 948 | verified | 1 | 1 of 1 | verified | no |
| EdDSA | 948 | verified | 1 | 1 of 1 | verified | no |
| ML-DSA-44 | 4,095 | rejected by the browser | 2 | 2 of 2 | verified | **yes** |
| SLH-DSA-SHA2-128s | 11,353 | rejected by the browser | 3 | 3 of 3 | rejected by the proxy (400) | no |
| SLH-DSA-SHA2-128f | 23,662 | rejected by the proxy (502) | 6 | 0 of 6 | rejected by the proxy (502) | no |

- **Rejected by the browser:** Chromium did not store the single cookie, whose name + value is 4,098 bytes for ML-DSA-44 and 11,356 for SLH-DSA-SHA2-128s; `BrowserContext.cookies()` listed no `jwt` cookie afterwards.
- **Rejected by the proxy (400):** SLH-DSA-SHA2-128s's three chunks were stored, but the verify request's 11,391-byte `Cookie` line is longer than nginx's 8,192-byte line: nginx logged `client sent too long header line` and answered 400, and the request never reached the application.
- **Rejected by the proxy (502):** SLH-DSA-SHA2-128f's issue response, measured straight from the application, has a 23,864-byte header block as one cookie and 24,263 bytes split, both over nginx's 16 KiB `proxy_buffer_size`: the application answered 200, and nginx logged `upstream sent too big header` and answered 502, so Chromium never saw a chunk.

**With nginx's buffers raised** (stack `limits-raised`; its [nginx.conf](results/cookies/20261118T105758Z-macos/limits-raised/nginx.conf) marks `--header-buffers 32k`, `large_client_header_buffers 4 32k`, and `--proxy-buffers 32k`, `proxy_buffer_size 32k; proxy_buffers 8 32k`, as not defaults):

| Configuration | Token | Single cookie | Chunks | Chunks stored | Split cookies | Moved |
| --- | ---: | --- | ---: | ---: | --- | --- |
| RS256 | 1,204 | verified | 1 | 1 of 1 | verified | no |
| ES256 | 948 | verified | 1 | 1 of 1 | verified | no |
| EdDSA | 948 | verified | 1 | 1 of 1 | verified | no |
| ML-DSA-44 | 4,095 | rejected by the browser | 2 | 2 of 2 | verified | **yes** |
| SLH-DSA-SHA2-128s | 11,353 | rejected by the browser | 3 | 3 of 3 | verified | **yes** |
| SLH-DSA-SHA2-128f | 23,662 | rejected by the browser | 6 | 6 of 6 | verified | **yes** |

With the raised buffers nginx passes every response and request, so the only limit left for the single cookie is Chromium's: SLH-DSA-SHA2-128f's 23,665-byte name + value is refused like the others. Every split verified; the application received SLH-DSA-SHA2-128f's request with 24,273 bytes of headers (11,934 for SLH-DSA-SHA2-128s), and Chromium sent its six chunks in index order.

**Boundary at the defaults.** The search sent ML-DSA-44's split token at pad 0 (4,095 bytes, 2 chunks: verified) and at pad 9,207 (16,383 bytes, 5 chunks: rejected by the proxy, a 502 at the issue, whose header block is 16,905 bytes), then bisected the padding in 15 probes:

| | Pad | Token | Chunks | Outcome | Largest chunk name + value | Cookie line | Issue response headers | Browser request headers |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| Largest verified | 3,035 | 8,154 | 3 | verified | 2,725 | 8,192 | 8,518 | 8,832 |
| First rejected | 3,036 | 8,155 | 3 | rejected by the proxy (400) | 2,726 | 8,193 | 8,519 | 8,833 |

The cookie line columns are calculated; the header blocks were measured. The 8,154-byte token's `Cookie` line is exactly 8,192 bytes, and one more byte of token makes nginx log `client sent too long header line` and answer 400 before the application sees the request. Every probe up to 8,154 bytes verified, and every larger one was rejected by nginx. Between the probes of 7,942 and 8,134 bytes the default count went from 2 chunks to 3 (at 8,001 bytes, by the format's rule) without changing the outcome, because every chunk stays far below Chromium's 4,096 bytes.

**Probes with the raised buffers:**

| Probe | Configuration | Pad | Token | Chunks | Largest chunk name + value | Chunks stored | Outcome | Cookie line | Issue response headers |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| Per cookie, at the limit | ML-DSA-44 | 3,053 | 8,178 | 2 | 4,096 | 2 of 2 | verified | 8,206 | 8,463 |
| Per cookie, over the limit | ML-DSA-44 | 3,054 | 8,179 | 2 | 4,097 | 1 of 2 | rejected by the browser | 8,207 | 8,464 |
| Cookie count, at the limit | ES256 | 0 | 948 | 180 | 16 | 180 of 180 | verified | 3,366 | 15,906 |
| Cookie count, over the limit | ES256 | 0 | 948 | 181 | 16 | 150 of 181 | rejected by the browser | 3,380 | 15,989 |

- **Per cookie:** the pads were calculated so that the larger of two chunks has a name + value of exactly 4,096 bytes, then 4,097. Chromium stored the first and dropped only the 4,097-byte chunk, which measures the limit Sprint 2 found for one cookie, now per chunk. The at-limit probe's `Cookie` line is 8,206 bytes, so it verified only because the header buffers were raised.
- **Cookie count:** 180 chunks of 5–6 characters were all stored and verified. With 181, `BrowserContext.cookies()` listed 150: once the 181st cookie arrived, Chromium evicted the 31 oldest, chunks 0 to 30, which matches its source (`kDomainMaxCookies` 180, `kDomainPurgeCookies` 30). Chromium then sent chunks 31 to 180, and the application answered 401 for the missing ones. The over-limit per-cookie probe ended the same way: Chromium sent only chunk 1, and the application answered 401. A split therefore shares 180 cookies per domain with everything else the site sets.

**Do chunks stay within nginx's limits?**

- **The 8,192-byte `Cookie` line:** no, not for SLH-DSA. Splitting changes how Chromium stores a token, not how it sends it: every chunk goes in the one `Cookie` header line, which grows by the chunk names. ML-DSA-44's 4,123-byte split line fits; SLH-DSA-SHA2-128s's 11,391 bytes and SLH-DSA-SHA2-128f's 23,730 bytes do not, and the largest split token that fit was 8,154 bytes.
- **Its total header buffers (4 × 8k, 32,768 bytes at the defaults):** never the limit here. One `Cookie` line cannot exceed one 8k buffer at the defaults, so the line limit always rejects first. With the buffers raised to 4 × 32k, the largest request header block Chromium sent was 24,370 bytes (SLH-DSA-SHA2-128f split), within one 32k buffer. Spreading the chunks over several header lines would bring the total into play, which HTTP/1.1 browsers do not do (see Limitations).
- **`proxy_buffer_size` (16 KiB here):** only SLH-DSA-SHA2-128f's issue response, 24,263 bytes split, does not fit; ML-DSA-44's is 4,380 bytes and SLH-DSA-SHA2-128s's 11,717. On WSL2 the default is 4 KiB, one x86_64 page, so the 4,380-byte ML-DSA-44 split response would not fit there either: derived from the measured header block and Sprint 2's 4 KiB boundary, not measured, since WSL2 was not run. The 180-cookie probe's 15,906-byte response would also exceed it.

### Missing and reordered chunks

**Measured on the raised stack.** http.client sent `GET /api/token/verify?timing=1&nonce=<32 hex digits>` through nginx with the cookies below. Token A is ML-DSA-44's 4,095-byte OIDC token, issued straight from the application split in three (`jwt.0.3`, `jwt.1.3`, `jwt.2.3`); token B is the same configuration with one character of padding, also split in three; `jwt.0.2` is the first chunk of A split in two. "Verify called" means the adapter's `verify_token` ran (`timing.verify_ns` was not null).

| Case | Cookies sent, in order | Status | Verified | Source | Verify called | Count | Received | Missing | Error |
| --- | --- | ---: | --- | --- | --- | ---: | --- | --- | --- |
| `in_order` | `jwt.0.3`, `jwt.1.3`, `jwt.2.3` | 200 | yes | split | yes | 3 | 0, 1, 2 | — | — |
| `reversed` | `jwt.2.3`, `jwt.1.3`, `jwt.0.3` | 200 | yes | split | yes | 3 | 2, 1, 0 | — | — |
| `rotated` | `jwt.1.3`, `jwt.2.3`, `jwt.0.3` | 200 | yes | split | yes | 3 | 1, 2, 0 | — | — |
| `among_other_cookies` | `a`, `jwt.2.3`, `jwt_old`, `jwt.0.3`, `theme`, `jwt.1.3` | 200 | yes | split | yes | 3 | 2, 0, 1 | — | — |
| `missing_0` | `jwt.1.3`, `jwt.2.3` | 401 | no | split | no | 3 | 1, 2 | 0 | incomplete chunks: 1 of 3 missing, index 0 |
| `missing_1` | `jwt.0.3`, `jwt.2.3` | 401 | no | split | no | 3 | 0, 2 | 1 | incomplete chunks: 1 of 3 missing, index 1 |
| `missing_2` | `jwt.0.3`, `jwt.1.3` | 401 | no | split | no | 3 | 0, 1 | 2 | incomplete chunks: 1 of 3 missing, index 2 |
| `duplicate` | `jwt.0.3`, `jwt.1.3`, `jwt.1.3`, `jwt.2.3` | 400 | no | split | no | 3 | 0, 1, 1, 2 | — | ambiguous chunks: index 1 was sent more than once |
| `conflicting_count` | `jwt.0.3`, `jwt.1.3`, `jwt.2.3`, `jwt.0.2` | 400 | no | split | no | null | 0, 1, 2, 0 | — | ambiguous chunks: the chunk cookies do not share one count (2, 3) |
| `out_of_range_index` | `jwt.0.3`, `jwt.1.3`, `jwt.2.3`, `jwt.3.3` | 400 | no | split | no | 3 | 0, 1, 2, 3 | — | ambiguous chunks: index 3 is out of range for 3 chunks |
| `mixed_tokens` | `jwt.0.3` (A), `jwt.1.3` (B), `jwt.2.3` (A) | 401 | no | split | yes | 3 | 0, 1, 2 | — | verification failed: Signature verification failed |
| `with_jwt_cookie` | `jwt.0.3`, `jwt.1.3`, `jwt.2.3`, `jwt` | 400 | no | null | no | — | — | — | more than one token: send the jwt.\<index\>.\<count\> chunk cookies alone, without a jwt cookie or a Bearer header |
| `with_bearer` | `jwt.0.3`, `jwt.1.3`, `jwt.2.3`, and `Authorization: Bearer` | 400 | no | null | no | — | — | — | more than one token: send the jwt.\<index\>.\<count\> chunk cookies alone, without a jwt cookie or a Bearer header |

Every case got the status the application's rules give it. Order does not matter: the application joins by index, and other cookies, including `jwt_old`, are ignored. Missing, repeated, conflicting, and out-of-range chunks are refused from the names alone, so `verify_token` never runs on a partial or ambiguous token. Chunks from two different tokens form a well-formed set, which only the signature check catches, as it would catch any altered token. A count from an earlier issue (`conflicting_count`) is what a browser would send if a new, shorter split did not overwrite an old chunk; the application refuses it rather than guess which chunks belong together.

**Order Chromium sent the chunks in.** In every split size-limit pair and probe that reached the application (`chunk_order` in `cookies.json`), Chromium sent the chunks it held in index order: 0 and 1 for ML-DSA-44, 0 to 2 and 0 to 5 for the SLH-DSA tokens on the raised stack, 0 to 179 for the 180-chunk probe, and 31 to 180 for the 181-chunk probe after the eviction. That is the order the `Set-Cookie` headers created them in, which Chromium uses for cookies with the same path. The application does not depend on it.

### Latency

The S3-01 workload ([END_TO_END_RESULTS.md](END_TO_END_RESULTS.md#workload)) ran twice, first with one `jwt` cookie and then with split cookies, each on a new stack: a closed loop of `GET /api/token/verify?timing=1&nonce=<32 hex digits>` requests with OIDC tokens, from http.client threads and from Chromium's test page, at concurrency 1 and 4, with 1 second of warm-up and 2 seconds measured per cell, `--header-buffers 32k`, `--proxy-buffers 32k`, and `--upstream-keepalive 64`. Size-control cells were off. Each cell's token was issued with the default attributes, as in S3-01. The single cookie is the baseline, not a Bearer header, so the comparison isolates the cost of splitting; Bearer comparisons are in [END_TO_END_RESULTS.md](END_TO_END_RESULTS.md). Every measured request verified: 144,255 with one cookie and 169,012 split, none failed, and every delivered cell had at least 2,118 verified requests. Chromium refused the single cookie of ML-DSA-44 and both SLH-DSA tokens, so those six browser cells of the cookie run were not delivered and sent no request.

Latency is the client-measured time from sending a request to reading its whole response body, in milliseconds; p95 is nearest-rank. The difference is the split mean minus the single-cookie mean, so a positive difference means splitting was slower. Chromium coarsens its timer to about 0.1 ms, so its medians and p95 values are multiples of 0.1 ms.

**http.client (direct), concurrency 1**

| Configuration | Token | Chunks | Cookie mean | Split mean | Difference | Cookie median | Split median | Cookie p95 | Split p95 | Cookie req/s | Split req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 0.203 | 0.197 | -0.006 | 0.202 | 0.197 | 0.218 | 0.209 | 4,892 | 5,046 |
| ES256 | 948 | 1 | 0.218 | 0.215 | -0.004 | 0.217 | 0.214 | 0.231 | 0.226 | 4,557 | 4,642 |
| EdDSA | 948 | 1 | 0.218 | 0.214 | -0.004 | 0.217 | 0.213 | 0.230 | 0.225 | 4,572 | 4,663 |
| ML-DSA-44 | 4,095 | 2 | 0.231 | 0.232 | +0.001 | 0.230 | 0.230 | 0.244 | 0.246 | 4,311 | 4,302 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | 0.418 | 0.435 | +0.017 | 0.418 | 0.435 | 0.432 | 0.451 | 2,385 | 2,290 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | 0.697 | 0.751 | +0.054 | 0.695 | 0.750 | 0.716 | 0.766 | 1,432 | 1,330 |

**http.client (direct), concurrency 4**

| Configuration | Token | Chunks | Cookie mean | Split mean | Difference | Cookie median | Split median | Cookie p95 | Split p95 | Cookie req/s | Split req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 0.647 | 0.637 | -0.010 | 0.624 | 0.607 | 0.951 | 0.955 | 6,166 | 6,266 |
| ES256 | 948 | 1 | 0.630 | 0.614 | -0.016 | 0.608 | 0.593 | 0.911 | 0.917 | 6,338 | 6,498 |
| EdDSA | 948 | 1 | 0.623 | 0.609 | -0.014 | 0.603 | 0.586 | 0.916 | 0.906 | 6,407 | 6,553 |
| ML-DSA-44 | 4,095 | 2 | 0.575 | 0.602 | +0.026 | 0.553 | 0.565 | 0.852 | 0.879 | 6,936 | 6,637 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | 1.107 | 1.369 | +0.262 | 1.083 | 1.235 | 1.605 | 2.365 | 3,610 | 2,917 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | 2.145 | 2.470 | +0.325 | 2.127 | 2.271 | 2.995 | 4.096 | 1,863 | 1,617 |

**Chromium (browser), concurrency 1**

| Configuration | Token | Chunks | Cookie mean | Split mean | Difference | Cookie median | Split median | Cookie p95 | Split p95 | Cookie req/s | Split req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 0.434 | 0.417 | -0.017 | 0.400 | 0.400 | 0.500 | 0.500 | 2,300 | 2,392 |
| ES256 | 948 | 1 | 0.477 | 0.482 | +0.005 | 0.500 | 0.500 | 0.600 | 0.600 | 2,095 | 2,073 |
| EdDSA | 948 | 1 | 0.459 | 0.485 | +0.025 | 0.400 | 0.500 | 0.500 | 0.600 | 2,175 | 2,062 |
| ML-DSA-44 | 4,095 | 2 | not delivered | 0.494 | — | — | 0.500 | — | 0.600 | — | 2,022 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | not delivered | 0.631 | — | — | 0.600 | — | 0.700 | — | 1,584 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | not delivered | 0.944 | — | — | 0.900 | — | 1.100 | — | 1,059 |

**Chromium (browser), concurrency 4**

| Configuration | Token | Chunks | Cookie mean | Split mean | Difference | Cookie median | Split median | Cookie p95 | Split p95 | Cookie req/s | Split req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 0.994 | 0.993 | -0.001 | 0.900 | 0.900 | 1.400 | 1.400 | 4,022 | 4,027 |
| ES256 | 948 | 1 | 1.005 | 0.976 | -0.029 | 0.900 | 0.900 | 1.400 | 1.300 | 3,978 | 4,099 |
| EdDSA | 948 | 1 | 0.981 | 0.977 | -0.004 | 0.900 | 0.900 | 1.300 | 1.300 | 4,074 | 4,091 |
| ML-DSA-44 | 4,095 | 2 | not delivered | 0.965 | — | — | 0.900 | — | 1.300 | — | 4,142 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | not delivered | 1.562 | — | — | 1.500 | — | 2.200 | — | 2,560 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | not delivered | 2.572 | — | — | 2.500 | — | 3.800 | — | 1,554 |

**Noise level.** EdDSA and ES256 tokens are the same size, so the difference between their means shows how much two cells differ without any change in size. With one cookie it is -0.001 ms from http.client at concurrency 1 and -0.007 ms at concurrency 4, and -0.018 and -0.024 ms from Chromium; split, -0.001 and -0.005 ms from http.client and +0.003 and +0.002 ms from Chromium. This measures noise within one run only; the two runs ran one after the other, always the single cookie first, so a drift between them affects every configuration's difference alike.

Where the difference is clearest, http.client at concurrency 1, the components show where it comes from (difference of each component's mean, split minus single cookie, in ms):

| Configuration | Chunks | Total | Transfer | Other handling | Verification |
| --- | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1 | -0.006 | -0.010 | +0.004 | +0.001 |
| ES256 | 1 | -0.004 | -0.009 | +0.004 | +0.002 |
| EdDSA | 1 | -0.004 | -0.010 | +0.003 | +0.002 |
| ML-DSA-44 | 2 | +0.001 | -0.009 | +0.006 | +0.003 |
| SLH-DSA-SHA2-128s | 3 | +0.017 | +0.010 | +0.009 | -0.002 |
| SLH-DSA-SHA2-128f | 6 | +0.054 | +0.016 | +0.013 | +0.025 |

- **http.client, concurrency 1:** other handling, the verify handler outside `verify_token`, grows with the number of chunks: 0.003–0.004 ms for one chunk, 0.006 ms for two, 0.009 ms for three, and 0.013 ms for six. That is consistent with the work splitting adds by design, the application parsing the chunk cookies and joining them. Transfer is 0.009–0.010 ms lower in the split run for every token of up to two chunks, which no size difference explains (the split request is 4–14 bytes longer), so it is drift between the two runs; for the SLH-DSA tokens transfer is 0.010 and 0.016 ms higher. ML-DSA-44's total difference, +0.001 ms, equals the noise level, and the classical configurations' -0.004 to -0.006 ms is the same drift. SLH-DSA-SHA2-128f's +0.025 ms of verification is not caused by splitting, since `verify_token` gets the same token either way; it is part of the run-to-run variation.
- **http.client, concurrency 4:** the classical configurations were 0.010–0.016 ms faster split, ML-DSA-44 0.026 ms slower, and SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f 0.262 and 0.325 ms slower, almost all of it in transfer, with much longer p95 tails (2.365 against 1.605 ms, 4.096 against 2.995 ms). Within these cells, `raw.csv.gz` shows the split run's transfer times stepping up partway through ML-DSA-44's cell, staying up through SLH-DSA-SHA2-128s's, and falling back before the end of SLH-DSA-SHA2-128f's, while the single-cookie cells are flat. A change in the middle of a cell is not a property of the token being sent, so these differences are reported as measured and not attributed to splitting; on this shared machine, other work is the likelier cause.
- **Chromium:** only the classical configurations can be compared, at -0.029 to +0.025 ms against same-size noise of up to 0.024 ms and a 0.1 ms timer: no effect is measurable. For the post-quantum configurations splitting is the difference between no request at all and a working cookie: split, Chromium sent ML-DSA-44's token at 0.494 ms per request at concurrency 1, close to the classical tokens' 0.417–0.485 ms.

**Modeled network cost (calculated, not measured).** Loopback makes transfer nearly free. From each run's `network_model`, the modeled upload time of the direct client's request on a new or idle TCP connection (the S3-01 model: bytes at the uplink rate plus one round trip per extra slow-start round, with an initial window of 14,600 bytes) grows by, at each illustrative profile:

| Configuration | Cookie request bytes | Split request bytes | Extra bytes | 100 Mbit/s, 10 ms RTT | 10 Mbit/s, 50 ms RTT | 1 Mbit/s, 100 ms RTT |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,350 | 1,354 | 4 | 0.000 | 0.003 | 0.032 |
| ES256 | 1,094 | 1,098 | 4 | 0.000 | 0.003 | 0.032 |
| EdDSA | 1,094 | 1,098 | 4 | 0.000 | 0.003 | 0.032 |
| ML-DSA-44 | 4,241 | 4,255 | 14 | 0.001 | 0.011 | 0.112 |
| SLH-DSA-SHA2-128s | 11,499 | 11,523 | 24 | 0.002 | 0.019 | 0.192 |
| SLH-DSA-SHA2-128f | 23,808 | 23,862 | 54 | 0.004 | 0.043 | 0.432 |

The extra bytes are the chunk names and separators. No request crosses into another slow-start round (SLH-DSA-SHA2-128f's needs two rounds either way), so the cost is serialization only, at most 0.432 ms per request on a 1 Mbit/s uplink. The issue response's extra `Set-Cookie` lines (up to 399 bytes more for SLH-DSA-SHA2-128f with production attributes, calculated in the plan) are sent once per issue, not per request, and are not modeled.

### Reproduce

From a clean checkout with the environment from [TRANSPORT.md](TRANSPORT.md#setup), with `TRANSPORT_ENV` set, `TMPDIR` unset (so the stacks' run directories land in `/tmp`), and no other load on the machine:

```bash
make cookies
# the same command, which make cookies runs with --output-dir results/cookies/<UTC time>-<platform>:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py cookies --header-buffers 32k --proxy-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir results/cookies/<YYYYMMDDTHHMMSSZ>-macos
# the same settings, from this run's cookies.json:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py cookies --settings results/cookies/20261118T105758Z-macos/cookies.json --output-dir results/cookies/<YYYYMMDDTHHMMSSZ>-macos
# one latency run alone, from its saved load.json:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --settings results/cookies/20261118T105758Z-macos/latency-split/load.json --output-dir /tmp/latency-split
```

The run took under 3 minutes. `--output-dir` must not exist yet or be empty. [TRANSPORT.md](TRANSPORT.md#the-cookies-command) describes every option and output file. The tables above come from `cookies.json`, and each latency cell's numbers can be recomputed from its rows in the `raw.csv.gz` files.

The recorded run's printed output: one line per configuration of the plan; per stack and configuration of the size limits (single cookie, then split with its chunk count and the chunks stored); the boundary; each probe; each chunk-handling case; and each latency row (single cookie, then split):

```text
plan     RS256               1,204 B   1 chunks  name+value  1,207 -> 1,211 B  Cookie line  1,218 ->  1,222 B  Set-Cookie  1,279 ->  1,283 B  cookie fits, split fits
plan     ES256                 948 B   1 chunks  name+value    951 ->   955 B  Cookie line    962 ->    966 B  Set-Cookie  1,023 ->  1,027 B  cookie fits, split fits
plan     EdDSA                 948 B   1 chunks  name+value    951 ->   955 B  Cookie line    962 ->    966 B  Set-Cookie  1,023 ->  1,027 B  cookie fits, split fits
plan     ML-DSA-44           4,095 B   2 chunks  name+value  4,098 -> 2,055 B  Cookie line  4,109 ->  4,123 B  Set-Cookie  4,170 ->  4,253 B  cookie over per-cookie, split fits
plan     SLH-DSA-SHA2-128s  11,353 B   3 chunks  name+value 11,356 -> 3,792 B  Cookie line 11,367 -> 11,391 B  Set-Cookie 11,428 -> 11,590 B  cookie over per-cookie+cookie-line, split over cookie-line
plan     SLH-DSA-SHA2-128f  23,662 B   6 chunks  name+value 23,665 -> 3,951 B  Cookie line 23,676 -> 23,730 B  Set-Cookie 23,737 -> 24,136 B  cookie over per-cookie+cookie-line, split over cookie-line
limits   limits-default  RS256               1,204 B  cookie verified                 split x1  verified                 stored 1/1
limits   limits-default  ES256                 948 B  cookie verified                 split x1  verified                 stored 1/1
limits   limits-default  EdDSA                 948 B  cookie verified                 split x1  verified                 stored 1/1
limits   limits-default  ML-DSA-44           4,095 B  cookie rejected by browser      split x2  verified                 stored 2/2  moved
limits   limits-default  SLH-DSA-SHA2-128s  11,353 B  cookie rejected by browser      split x3  rejected by proxy        stored 3/3
limits   limits-default  SLH-DSA-SHA2-128f  23,662 B  cookie rejected by proxy        split x6  rejected by proxy        stored 0/6
limits   limits-raised   RS256               1,204 B  cookie verified                 split x1  verified                 stored 1/1
limits   limits-raised   ES256                 948 B  cookie verified                 split x1  verified                 stored 1/1
limits   limits-raised   EdDSA                 948 B  cookie verified                 split x1  verified                 stored 1/1
limits   limits-raised   ML-DSA-44           4,095 B  cookie rejected by browser      split x2  verified                 stored 2/2  moved
limits   limits-raised   SLH-DSA-SHA2-128s  11,353 B  cookie rejected by browser      split x3  verified                 stored 3/3  moved
limits   limits-raised   SLH-DSA-SHA2-128f  23,662 B  cookie rejected by browser      split x6  verified                 stored 6/6  moved
boundary ML-DSA-44  limits-default  split, oidc claims  largest verified 8,154 B (pad 3,035, 3 chunks)  first rejected 8,155 B (pad 3,036, 3 chunks) rejected by proxy  15 probes
probe    per_cookie    at_limit    ML-DSA-44  pad 3,053   8,178 B    2 chunks  largest name+value 4,096 B  stored 2/2  verified
probe    per_cookie    over_limit  ML-DSA-44  pad 3,054   8,179 B    2 chunks  largest name+value 4,097 B  stored 1/2  rejected by browser
probe    cookie_count  at_limit    ES256      pad     0     948 B  180 chunks  largest name+value    16 B  stored 180/180  verified
probe    cookie_count  over_limit  ES256      pad     0     948 B  181 chunks  largest name+value    16 B  stored 150/181  rejected by browser
handling in_order              status 200  verified      source split  verify_token called  received [0, 1, 2]
handling reversed              status 200  verified      source split  verify_token called  received [2, 1, 0]
handling rotated               status 200  verified      source split  verify_token called  received [1, 2, 0]
handling among_other_cookies   status 200  verified      source split  verify_token called  received [2, 0, 1]
handling missing_0             status 401  not verified  source split  verify_token not called  received [1, 2]  missing [0]
handling missing_1             status 401  not verified  source split  verify_token not called  received [0, 2]  missing [1]
handling missing_2             status 401  not verified  source split  verify_token not called  received [0, 1]  missing [2]
handling duplicate             status 400  not verified  source split  verify_token not called  received [0, 1, 1, 2]
handling conflicting_count     status 400  not verified  source split  verify_token not called  received [0, 1, 2, 0]
handling out_of_range_index    status 400  not verified  source split  verify_token not called  received [0, 1, 2, 3]
handling mixed_tokens          status 401  not verified  source split  verify_token called  received [0, 1, 2]
handling with_jwt_cookie       status 400  not verified  source -      verify_token not called
handling with_bearer           status 400  not verified  source -      verify_token not called
latency  direct  c=1   RS256               1,204 B x1  mean 0.203 -> 0.197 ms (-0.006)  median 0.202 -> 0.197  p95 0.218 -> 0.209  4,891.6 -> 5,045.9 req/s
latency  direct  c=1   ES256                 948 B x1  mean 0.218 -> 0.215 ms (-0.004)  median 0.217 -> 0.214  p95 0.231 -> 0.226  4,557.3 -> 4,642.0 req/s
latency  direct  c=1   EdDSA                 948 B x1  mean 0.218 -> 0.214 ms (-0.004)  median 0.217 -> 0.213  p95 0.230 -> 0.225  4,572.0 -> 4,662.7 req/s
latency  direct  c=1   ML-DSA-44           4,095 B x2  mean 0.231 -> 0.232 ms (+0.001)  median 0.230 -> 0.230  p95 0.244 -> 0.246  4,310.6 -> 4,301.7 req/s
latency  direct  c=1   SLH-DSA-SHA2-128s  11,353 B x3  mean 0.418 -> 0.435 ms (+0.017)  median 0.418 -> 0.435  p95 0.432 -> 0.451  2,384.5 -> 2,290.3 req/s
latency  direct  c=1   SLH-DSA-SHA2-128f  23,662 B x6  mean 0.697 -> 0.751 ms (+0.054)  median 0.695 -> 0.750  p95 0.716 -> 0.766  1,432.3 -> 1,329.6 req/s
latency  direct  c=4   RS256               1,204 B x1  mean 0.647 -> 0.637 ms (-0.010)  median 0.624 -> 0.607  p95 0.951 -> 0.955  6,166.4 -> 6,265.7 req/s
latency  direct  c=4   ES256                 948 B x1  mean 0.630 -> 0.614 ms (-0.016)  median 0.608 -> 0.593  p95 0.911 -> 0.917  6,338.1 -> 6,498.2 req/s
latency  direct  c=4   EdDSA                 948 B x1  mean 0.623 -> 0.609 ms (-0.014)  median 0.603 -> 0.586  p95 0.916 -> 0.906  6,407.4 -> 6,552.9 req/s
latency  direct  c=4   ML-DSA-44           4,095 B x2  mean 0.575 -> 0.602 ms (+0.026)  median 0.553 -> 0.565  p95 0.852 -> 0.879  6,936.2 -> 6,637.2 req/s
latency  direct  c=4   SLH-DSA-SHA2-128s  11,353 B x3  mean 1.107 -> 1.369 ms (+0.262)  median 1.083 -> 1.235  p95 1.605 -> 2.365  3,609.8 -> 2,917.2 req/s
latency  direct  c=4   SLH-DSA-SHA2-128f  23,662 B x6  mean 2.145 -> 2.470 ms (+0.325)  median 2.127 -> 2.271  p95 2.995 -> 4.096  1,862.6 -> 1,616.9 req/s
latency  browser c=1   RS256               1,204 B x1  mean 0.434 -> 0.417 ms (-0.017)  median 0.400 -> 0.400  p95 0.500 -> 0.500  2,300.5 -> 2,392.5 req/s
latency  browser c=1   ES256                 948 B x1  mean 0.477 -> 0.482 ms (+0.005)  median 0.500 -> 0.500  p95 0.600 -> 0.600  2,094.6 -> 2,072.7 req/s
latency  browser c=1   EdDSA                 948 B x1  mean 0.459 -> 0.485 ms (+0.025)  median 0.400 -> 0.500  p95 0.500 -> 0.600  2,174.8 -> 2,061.6 req/s
latency  browser c=1   ML-DSA-44           4,095 B x2  no verified request: cookie not delivered
latency  browser c=1   SLH-DSA-SHA2-128s  11,353 B x3  no verified request: cookie not delivered
latency  browser c=1   SLH-DSA-SHA2-128f  23,662 B x6  no verified request: cookie not delivered
latency  browser c=4   RS256               1,204 B x1  mean 0.994 -> 0.993 ms (-0.001)  median 0.900 -> 0.900  p95 1.400 -> 1.400  4,021.6 -> 4,027.0 req/s
latency  browser c=4   ES256                 948 B x1  mean 1.005 -> 0.976 ms (-0.029)  median 0.900 -> 0.900  p95 1.400 -> 1.300  3,978.1 -> 4,098.6 req/s
latency  browser c=4   EdDSA                 948 B x1  mean 0.981 -> 0.977 ms (-0.004)  median 0.900 -> 0.900  p95 1.300 -> 1.300  4,074.0 -> 4,090.7 req/s
latency  browser c=4   ML-DSA-44           4,095 B x2  no verified request: cookie not delivered
latency  browser c=4   SLH-DSA-SHA2-128s  11,353 B x3  no verified request: cookie not delivered
latency  browser c=4   SLH-DSA-SHA2-128f  23,662 B x6  no verified request: cookie not delivered
Saved the results to results/cookies/20261118T105758Z-macos
```

### Limitations

- **WSL2 was not run.** The `cookies` command has not been run on WSL2, so every measurement here is from this Mac. On WSL2, nginx's default `proxy_buffer_size` is 4 KiB, so at the defaults even ML-DSA-44's 4,380-byte split issue response would get 502 from nginx; that is derived from the measured header block, not measured.
- **Loopback only.** Both latency runs ran over loopback on one machine; the network cost is only calculated, not measured, with S3-01's assumptions (upload only, no loss, no TLS or HTTP/2 framing) and its illustrative profiles.
- **One run, in a fixed order.** Each transport ran once, the single cookie first, so run-to-run variation was not measured and a drift between the two runs cannot be told apart from an effect of splitting. EdDSA's difference from ES256 shows the noise within a run; the concurrency-4 differences are reported but not attributed.
- **Chromium only, one browser profile.** Firefox and Safari have their own per-cookie and per-domain limits and eviction rules, which were not measured.
- **HTTP/1.1 without TLS.** Chromium sends all cookies in one `Cookie` header line over HTTP/1.1, which is what makes nginx's line limit apply to the whole split. Over HTTP/2, browsers may send each cookie as a separate header field (RFC 9113 §8.2.3), so the line limit could apply per chunk instead, while header-list limits apply to the total; HTTPS and HTTP/2 are S3-04's work.
- **Stale chunks are refused, not cleaned up.** If a later issue splits a token into fewer chunks, the old higher-index chunks stay in the browser until they expire, and the application answers 400 for the conflicting counts (the `conflicting_count` case). A deployment would have to delete stale chunks when it issues new ones (for example with `Max-Age=0` for every old name); this run does not measure that.
- **Not the default limits.** The raised-limits stack and both latency stacks use `--header-buffers 32k` and `--proxy-buffers 32k`, and the latency stacks the non-default `--upstream-keepalive 64`, as recorded in `cookies.json` and marked in each `nginx.conf`; the default-limits stack keeps every default.
- **Tokens in two logs.** The size-limit phases' `browser.log.gz` files hold the tokens and chunks Chromium handled, and nginx's error log in `limits-default/` holds a truncated prefix of each rejected `Cookie` line (`client sent too long header line`); all were signed with discarded experiment keys.
- **Machine state.** The other candidates for this task were being built and tested on the same Mac, sharing its CPU and ephemeral ports; none of their stacks or tests ran when this run started, but another candidate's test suite started in its last seconds. The concurrency-4 latency differences may reflect such activity, and the kept implementation's run is to be recorded again on an idle Mac.

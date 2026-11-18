# Sprint 3 results: mitigations

Mitigations for the token sizes that break transport in Sprint 2, measured through the same stack, Chromium or http.client → nginx → waitress → application, and with the S3-01 workload (stack and command: [TRANSPORT.md](TRANSPORT.md#the-claims-command); task: [PROGRESS.md](PROGRESS.md#s3-02--compare-mitigations); Sprint 2 limits: [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md); S3-01 workload: [END_TO_END_RESULTS.md](END_TO_END_RESULTS.md)). This document covers S3-02's first mitigation, smaller claim sets. Cookie splitting and reference tokens are measured in later runs, which add their own sections here:

- **Smaller claim sets:** covered below.
- **Cookie splitting:** not covered yet.
- **Reference tokens:** not covered yet.

## Smaller claim sets

The question: how much does each configuration's token shrink when it carries only essential claims, and does that move any Sprint 2 size limit? The answer from this run:

- **Size:** every token shrinks by the same 641 bytes, from the 22-claim OpenID Connect fixture to its 5 required claims. That is 53.2% of RS256's token, 67.6% of ES256's and EdDSA's, 15.7% of ML-DSA-44's, and only 5.6% and 2.7% of SLH-DSA-SHA2-128s's and SLH-DSA-SHA2-128f's.
- **Limits:** exactly one verdict moves. ML-DSA-44's cookie goes from 4,095 to 3,454 bytes, under Chromium's 4,096-byte cookie name + value limit and under WSL2's nginx response buffer, so the browser that rejected it with OIDC claims now stores and sends it. Nothing moves for Bearer headers or for SLH-DSA, whose header and signature alone exceed every default limit.
- **Latency:** over loopback, the smaller payload saves 0.033–0.034 ms per request for the classical configurations and 0.016 ms for ML-DSA-44 from http.client at concurrency 1, and nothing measurable for SLH-DSA or from Chromium. On a real uplink, the calculated saving is 0.051–5.128 ms per request for every configuration.

Every number below comes from one run on the team's Mac (Apple M5 Pro, 18 cores, macOS 26.5.1, arm64, 16 KiB memory pages; Python 3.15.2, Playwright 1.64.1, Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2 with its default 4 threads), recorded with `make claims` on November 18, 2026 (UTC; the evening of November 17 local time) at commit `828cf05`, with no uncommitted change to `scripts/` or `fixtures/`. Every token was signed with **ephemeral experiment keys, not production credentials**: each key was generated in memory for the run and discarded, so the tokens in its logs are not credentials either.

| Machine | Run | Files |
| --- | --- | --- |
| Apple M5 Pro (macOS) | [`20261118T000856Z-macos`](results/claims/20261118T000856Z-macos/) | [claims.json](results/claims/20261118T000856Z-macos/claims.json) |

| Phase | Evidence |
| --- | --- |
| Size limits, at the documented defaults | [nginx.conf](results/claims/20261118T000856Z-macos/limits/nginx.conf), [app.log.gz](results/claims/20261118T000856Z-macos/limits/logs/app.log.gz), [browser.log.gz](results/claims/20261118T000856Z-macos/limits/logs/browser.log.gz), [proxy-access.log.gz](results/claims/20261118T000856Z-macos/limits/logs/proxy-access.log.gz), [proxy-error.log.gz](results/claims/20261118T000856Z-macos/limits/logs/proxy-error.log.gz) |
| Latency, OIDC claims | [load.json](results/claims/20261118T000856Z-macos/latency-oidc/load.json), [raw.csv.gz](results/claims/20261118T000856Z-macos/latency-oidc/raw.csv.gz), [logs](results/claims/20261118T000856Z-macos/latency-oidc/logs/), [nginx.conf](results/claims/20261118T000856Z-macos/latency-oidc/nginx.conf) |
| Latency, essential claims | [load.json](results/claims/20261118T000856Z-macos/latency-essential/load.json), [raw.csv.gz](results/claims/20261118T000856Z-macos/latency-essential/raw.csv.gz), [logs](results/claims/20261118T000856Z-macos/latency-essential/logs/), [nginx.conf](results/claims/20261118T000856Z-macos/latency-essential/nginx.conf) |
| Sprint 2 boundaries (WSL2, committed earlier) | [cookie-default/sweep.json](results/transport/20261113T074114Z-wsl2/cookie-default/sweep.json), [cookie-16k/sweep.json](results/transport/20261113T074114Z-wsl2/cookie-16k/sweep.json), [bearer-default/sweep.json](results/transport/20261113T074114Z-wsl2/bearer-default/sweep.json) |

`claims.json` holds the settings, the environment, the claim sets, the token sizes, the derived Sprint 2 verdicts, every size-limit pair with its evidence and nonces, and the latency comparison; each latency directory is exactly what `load --output-dir` writes. The logs are gzip-compressed (`gzip -dc`). `claims.json`, both `load.json` and `raw.csv.gz` files, and every `app.log.gz` and `proxy-access.log.gz` hold no token. The size-limits phase's `browser.log.gz` holds the tokens Chromium sent and received, and its `proxy-error.log.gz` holds nginx's own truncated prefix of each of the four rejected Bearer header lines.

**Machine state.** No other candidate's stack, load run, or test suite was running: before the run, the command waited until none had run for 30 seconds and 188 sockets were in TIME_WAIT, and a check every 2 seconds during the run found none. A `make serve` stack started earlier from the main checkout (its own nginx and waitress) was running and was not used by the run. Which desktop applications were open was not recorded. An earlier recording the same evening overlapped another candidate's `claims` run for its whole length and was discarded.

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

**Measured on this Mac at the documented default limits.** One stack with no raised limit (its [nginx.conf](results/claims/20261118T000856Z-macos/limits/nginx.conf) has no `Not a default` line) and headless Chromium sent each configuration's OIDC and essential token once as a `jwt` cookie with production attributes (`Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600`) and once as an `Authorization: Bearer` header, and named the rejecting layer of each rejected pair from every layer's log. Every one of the 24 tokens also verified when sent straight to the application.

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

The S3-01 workload ([END_TO_END_RESULTS.md](END_TO_END_RESULTS.md#workload)) ran twice, first with OIDC claims and then with the essential claims, each on a new stack: a closed loop of `GET /api/token/verify?timing=1&nonce=<32 hex digits>` requests with the token in an `Authorization: Bearer` header, from http.client threads and from Chromium's test page, at concurrency 1 and 4, with 1 second of warm-up and 2 seconds measured per cell, `--header-buffers 32k`, and `--upstream-keepalive 64`. Size-control cells were off: they answer a different question. Every measured request verified: 171,930 with OIDC claims and 188,726 with essential claims, none failed, and every cell had at least 2,071 verified requests.

Latency is the client-measured time from sending a request to reading its whole response body, in milliseconds; p95 is nearest-rank. The difference is the essential mean minus the OIDC mean, so a negative difference means the essential claims were faster. Chromium coarsens its timer to about 0.1 ms, so its medians and p95 values are multiples of 0.1 ms.

**http.client (direct), concurrency 1**

| Configuration | OIDC token | Essential token | OIDC mean | Essential mean | Difference | OIDC median | Essential median | OIDC p95 | Essential p95 | OIDC req/s | Essential req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 563 | 0.202 | 0.169 | -0.033 | 0.201 | 0.168 | 0.220 | 0.184 | 4,917 | 5,881 |
| ES256 | 948 | 307 | 0.217 | 0.183 | -0.034 | 0.216 | 0.183 | 0.234 | 0.195 | 4,579 | 5,440 |
| EdDSA | 948 | 307 | 0.219 | 0.186 | -0.033 | 0.217 | 0.185 | 0.238 | 0.201 | 4,544 | 5,350 |
| ML-DSA-44 | 4,095 | 3,454 | 0.231 | 0.215 | -0.016 | 0.230 | 0.214 | 0.245 | 0.233 | 4,310 | 4,627 |
| SLH-DSA-SHA2-128s | 11,353 | 10,712 | 0.406 | 0.405 | -0.002 | 0.405 | 0.403 | 0.426 | 0.421 | 2,455 | 2,465 |
| SLH-DSA-SHA2-128f | 23,662 | 23,021 | 0.685 | 0.691 | +0.006 | 0.683 | 0.686 | 0.710 | 0.726 | 1,457 | 1,445 |

**http.client (direct), concurrency 4**

| Configuration | OIDC token | Essential token | OIDC mean | Essential mean | Difference | OIDC median | Essential median | OIDC p95 | Essential p95 | OIDC req/s | Essential req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 563 | 0.651 | 0.551 | -0.101 | 0.626 | 0.529 | 0.963 | 0.828 | 6,130 | 7,250 |
| ES256 | 948 | 307 | 0.625 | 0.532 | -0.093 | 0.604 | 0.512 | 0.912 | 0.798 | 6,390 | 7,507 |
| EdDSA | 948 | 307 | 0.618 | 0.516 | -0.103 | 0.596 | 0.493 | 0.925 | 0.772 | 6,456 | 7,738 |
| ML-DSA-44 | 4,095 | 3,454 | 0.543 | 0.525 | -0.018 | 0.521 | 0.489 | 0.795 | 0.791 | 7,352 | 7,604 |
| SLH-DSA-SHA2-128s | 11,353 | 10,712 | 1.101 | 1.068 | -0.032 | 1.074 | 1.045 | 1.611 | 1.585 | 3,629 | 3,738 |
| SLH-DSA-SHA2-128f | 23,662 | 23,021 | 2.126 | 2.045 | -0.082 | 2.103 | 2.018 | 3.089 | 2.934 | 1,879 | 1,954 |

**Chromium (browser), concurrency 1**

| Configuration | OIDC token | Essential token | OIDC mean | Essential mean | Difference | OIDC median | Essential median | OIDC p95 | Essential p95 | OIDC req/s | Essential req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 563 | 0.428 | 0.401 | -0.028 | 0.400 | 0.400 | 0.500 | 0.500 | 2,333 | 2,494 |
| ES256 | 948 | 307 | 0.461 | 0.398 | -0.063 | 0.400 | 0.400 | 0.600 | 0.500 | 2,167 | 2,509 |
| EdDSA | 948 | 307 | 0.454 | 0.517 | +0.063 | 0.400 | 0.500 | 0.500 | 0.800 | 2,201 | 1,932 |
| ML-DSA-44 | 4,095 | 3,454 | 0.496 | 0.491 | -0.004 | 0.500 | 0.500 | 0.600 | 0.700 | 2,016 | 2,034 |
| SLH-DSA-SHA2-128s | 11,353 | 10,712 | 0.621 | 0.627 | +0.006 | 0.600 | 0.600 | 0.700 | 0.800 | 1,608 | 1,593 |
| SLH-DSA-SHA2-128f | 23,662 | 23,021 | 0.917 | 0.966 | +0.048 | 0.900 | 0.900 | 1.000 | 1.200 | 1,089 | 1,035 |

**Chromium (browser), concurrency 4**

| Configuration | OIDC token | Essential token | OIDC mean | Essential mean | Difference | OIDC median | Essential median | OIDC p95 | Essential p95 | OIDC req/s | Essential req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 563 | 0.983 | 0.914 | -0.069 | 0.900 | 0.800 | 1.400 | 1.300 | 4,069 | 4,376 |
| ES256 | 948 | 307 | 0.977 | 0.950 | -0.027 | 0.900 | 0.900 | 1.300 | 1.400 | 4,091 | 4,207 |
| EdDSA | 948 | 307 | 1.029 | 0.913 | -0.116 | 0.900 | 0.800 | 1.400 | 1.200 | 3,886 | 4,379 |
| ML-DSA-44 | 4,095 | 3,454 | 0.985 | 0.928 | -0.056 | 0.900 | 0.800 | 1.300 | 1.300 | 4,060 | 4,306 |
| SLH-DSA-SHA2-128s | 11,353 | 10,712 | 1.485 | 1.421 | -0.065 | 1.400 | 1.300 | 2.100 | 2.000 | 2,691 | 2,814 |
| SLH-DSA-SHA2-128f | 23,662 | 23,021 | 2.438 | 2.406 | -0.033 | 2.400 | 2.400 | 3.600 | 3.600 | 1,639 | 1,660 |

**Noise level.** EdDSA and ES256 tokens are the same size in both runs, so the difference between their means shows how much two cells differ without any change in size. From http.client at concurrency 1 it is +0.002 ms with OIDC claims and +0.003 ms with essential claims; at concurrency 4, -0.006 and -0.016 ms. From Chromium it is -0.007 and +0.119 ms at concurrency 1, and +0.052 and -0.037 ms at concurrency 4.

Where the saving is clear, http.client at concurrency 1, the components show where it comes from (difference of each component's mean, essential minus OIDC, in ms):

| Configuration | Total | Transfer | Other handling | Verification |
| --- | ---: | ---: | ---: | ---: |
| RS256 | -0.033 | -0.016 | -0.003 | -0.014 |
| ES256 | -0.034 | -0.018 | -0.004 | -0.013 |
| EdDSA | -0.033 | -0.016 | -0.004 | -0.013 |
| ML-DSA-44 | -0.016 | -0.012 | -0.003 | -0.001 |
| SLH-DSA-SHA2-128s | -0.002 | -0.003 | -0.003 | +0.004 |
| SLH-DSA-SHA2-128f | +0.006 | +0.006 | -0.002 | +0.002 |

- **http.client, concurrency 1:** RS256, ES256, and EdDSA are 0.033–0.034 ms faster with the essential claims, more than ten times the +0.002 to +0.003 ms noise, and their throughput rises accordingly (ES256: 4,579 to 5,440 req/s). About half of it is transfer (the 641 fewer bytes through both connections) and the rest is verification and other handling: `verify_token` decodes and parses a smaller payload and checks fewer claims. ML-DSA-44 saves 0.016 ms, most of it in transfer. SLH-DSA-SHA2-128s (-0.002 ms) and SLH-DSA-SHA2-128f (+0.006 ms) show no saving beyond the noise: 641 bytes are a small part of their tokens. Because the two runs ran one after the other, these two rows also show that the later run was not faster overall.
- **http.client, concurrency 4:** the classical configurations are 0.093–0.103 ms faster, against noise of 0.006–0.016 ms; ML-DSA-44 is 0.018 ms faster, and the SLH-DSA configurations 0.032 and 0.082 ms. At this concurrency a request also waits for the other workers' requests in waitress, so smaller requests shorten the queue too.
- **Chromium:** the differences range from -0.116 to +0.063 ms with no consistent sign, against noise of up to 0.119 ms, so no effect is measurable from the browser.

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
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py claims --settings results/claims/20261118T000856Z-macos/claims.json --output-dir results/claims/<YYYYMMDDTHHMMSSZ>-macos
# one latency run alone, from its saved load.json:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --settings results/claims/20261118T000856Z-macos/latency-essential/load.json --output-dir /tmp/latency-essential
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
latency  direct  c=1   RS256               1,204 ->    563 B  mean 0.202 -> 0.169 ms (-0.033)  median 0.201 -> 0.168  p95 0.220 -> 0.184  4,916.7 -> 5,880.7 req/s
latency  direct  c=1   ES256                 948 ->    307 B  mean 0.217 -> 0.183 ms (-0.034)  median 0.216 -> 0.183  p95 0.234 -> 0.195  4,578.7 -> 5,440.3 req/s
latency  direct  c=1   EdDSA                 948 ->    307 B  mean 0.219 -> 0.186 ms (-0.033)  median 0.217 -> 0.185  p95 0.238 -> 0.201  4,543.6 -> 5,350.4 req/s
latency  direct  c=1   ML-DSA-44           4,095 ->  3,454 B  mean 0.231 -> 0.215 ms (-0.016)  median 0.230 -> 0.214  p95 0.245 -> 0.233  4,309.9 -> 4,627.3 req/s
latency  direct  c=1   SLH-DSA-SHA2-128s  11,353 -> 10,712 B  mean 0.406 -> 0.405 ms (-0.002)  median 0.405 -> 0.403  p95 0.426 -> 0.421  2,455.1 -> 2,465.1 req/s
latency  direct  c=1   SLH-DSA-SHA2-128f  23,662 -> 23,021 B  mean 0.685 -> 0.691 ms (+0.006)  median 0.683 -> 0.686  p95 0.710 -> 0.726  1,457.0 -> 1,444.8 req/s
latency  direct  c=4   RS256               1,204 ->    563 B  mean 0.651 -> 0.551 ms (-0.101)  median 0.626 -> 0.529  p95 0.963 -> 0.828  6,129.8 -> 7,250.3 req/s
latency  direct  c=4   ES256                 948 ->    307 B  mean 0.625 -> 0.532 ms (-0.093)  median 0.604 -> 0.512  p95 0.912 -> 0.798  6,389.6 -> 7,507.3 req/s
latency  direct  c=4   EdDSA                 948 ->    307 B  mean 0.618 -> 0.516 ms (-0.103)  median 0.596 -> 0.493  p95 0.925 -> 0.772  6,455.6 -> 7,738.4 req/s
latency  direct  c=4   ML-DSA-44           4,095 ->  3,454 B  mean 0.543 -> 0.525 ms (-0.018)  median 0.521 -> 0.489  p95 0.795 -> 0.791  7,352.3 -> 7,603.5 req/s
latency  direct  c=4   SLH-DSA-SHA2-128s  11,353 -> 10,712 B  mean 1.101 -> 1.068 ms (-0.032)  median 1.074 -> 1.045  p95 1.611 -> 1.585  3,628.8 -> 3,738.4 req/s
latency  direct  c=4   SLH-DSA-SHA2-128f  23,662 -> 23,021 B  mean 2.126 -> 2.045 ms (-0.082)  median 2.103 -> 2.018  p95 3.089 -> 2.934  1,878.7 -> 1,953.9 req/s
latency  browser c=1   RS256               1,204 ->    563 B  mean 0.428 -> 0.401 ms (-0.028)  median 0.400 -> 0.400  p95 0.500 -> 0.500  2,333.2 -> 2,493.8 req/s
latency  browser c=1   ES256                 948 ->    307 B  mean 0.461 -> 0.398 ms (-0.063)  median 0.400 -> 0.400  p95 0.600 -> 0.500  2,167.1 -> 2,509.0 req/s
latency  browser c=1   EdDSA                 948 ->    307 B  mean 0.454 -> 0.517 ms (+0.063)  median 0.400 -> 0.500  p95 0.500 -> 0.800  2,200.9 -> 1,932.0 req/s
latency  browser c=1   ML-DSA-44           4,095 ->  3,454 B  mean 0.496 -> 0.491 ms (-0.004)  median 0.500 -> 0.500  p95 0.600 -> 0.700  2,015.9 -> 2,033.7 req/s
latency  browser c=1   SLH-DSA-SHA2-128s  11,353 -> 10,712 B  mean 0.621 -> 0.627 ms (+0.006)  median 0.600 -> 0.600  p95 0.700 -> 0.800  1,607.6 -> 1,593.2 req/s
latency  browser c=1   SLH-DSA-SHA2-128f  23,662 -> 23,021 B  mean 0.917 -> 0.966 ms (+0.048)  median 0.900 -> 0.900  p95 1.000 -> 1.200  1,089.3 -> 1,035.0 req/s
latency  browser c=4   RS256               1,204 ->    563 B  mean 0.983 -> 0.914 ms (-0.069)  median 0.900 -> 0.800  p95 1.400 -> 1.300  4,068.6 -> 4,376.2 req/s
latency  browser c=4   ES256                 948 ->    307 B  mean 0.977 -> 0.950 ms (-0.027)  median 0.900 -> 0.900  p95 1.300 -> 1.400  4,091.1 -> 4,207.4 req/s
latency  browser c=4   EdDSA                 948 ->    307 B  mean 1.029 -> 0.913 ms (-0.116)  median 0.900 -> 0.800  p95 1.400 -> 1.200  3,885.7 -> 4,379.2 req/s
latency  browser c=4   ML-DSA-44           4,095 ->  3,454 B  mean 0.985 -> 0.928 ms (-0.056)  median 0.900 -> 0.800  p95 1.300 -> 1.300  4,059.8 -> 4,306.5 req/s
latency  browser c=4   SLH-DSA-SHA2-128s  11,353 -> 10,712 B  mean 1.485 -> 1.421 ms (-0.065)  median 1.400 -> 1.300  p95 2.100 -> 2.000  2,691.3 -> 2,813.8 req/s
latency  browser c=4   SLH-DSA-SHA2-128f  23,662 -> 23,021 B  mean 2.438 -> 2.406 ms (-0.033)  median 2.400 -> 2.400  p95 3.600 -> 3.600  1,638.9 -> 1,660.3 req/s
Saved the results to results/claims/20261118T000856Z-macos
```

### Limitations

- **WSL2 has not been run yet.** The `claims` command has not been run on WSL2; the derived verdicts come from Sprint 2's WSL2 sweeps, but the measured size limits and latency are from this Mac only. On WSL2 the measured cookie verdicts should follow cookie-default, where nginx's 4 KiB buffer is the first limit.
- **Loopback only.** Both latency runs ran over loopback on one machine; the network saving is only calculated.
- **One run per claim set.** Each claim set ran once, the OIDC run first, so run-to-run variation was not measured; within the run, EdDSA's difference from ES256 shows the noise level.
- **Illustrative fixture values.** The fixture's values (an `example.test` issuer, a made-up subject, a name and an email address) are illustrative. The 641-byte saving is the size of the dropped claims' values; a real provider's claims could be larger or smaller.
- **The essential set is a team assumption.** It is OpenID Connect's five required ID Token claims; other plausible sets, such as RFC 9068's access-token claims (adding `client_id` and `jti`) or keeping `roles` for authorization, were not measured. Changing the fixture file and rerunning `make claims` would measure one.
- **The dropped claims' cost is not measured.** Getting them from the userinfo endpoint or a server-side session adds a lookup that a self-contained token avoids.
- **Tokens in two logs.** nginx's error log in `limits/` holds a truncated prefix of each rejected Bearer header line (`client sent too long header line`), as Sprint 2's logs do, and `browser.log.gz` in `limits/` holds the tokens the browser handled; all were signed with discarded experiment keys.
- **Not the default limits for latency.** The latency stacks use `--header-buffers 32k` and the non-default `--upstream-keepalive 64`, as S3-01 did; the size-limits stack keeps every default.
- **Derived cookie verdicts use the default attributes.** The Sprint 2 cookie sweeps used `Path=/; HttpOnly; SameSite=Strict`, so their `Set-Cookie` lines were 22 bytes shorter than with the production attributes used here. That matters only at cookie-default, where nginx counts the whole response header block, and changes no verdict: the smallest headroom of a token that fits there is ML-DSA-44's +461 bytes.
- **One browser, one size per pair, HTTP/1.1 without TLS.** Only Chromium was used, each size-limit pair was sent once at the fixture's size (not swept), and HTTPS and HTTP/2 are S3-04's work.
- **Machine state.** No other candidate's run was active (checked every 2 seconds), but an unused `make serve` stack was running, and which desktop applications were open was not recorded. An earlier recording that overlapped another candidate's run was discarded.

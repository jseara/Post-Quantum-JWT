# Sprint 3 results: mitigations

Mitigations for the token sizes that break transport in Sprint 2, measured through the same stack, Chromium or http.client → nginx → waitress → application, and with the S3-01 workload (stack and commands: [TRANSPORT.md](TRANSPORT.md#the-claims-command) for the `claims` command, [TRANSPORT.md](TRANSPORT.md#the-cookies-command) for the `cookies` command, and [TRANSPORT.md](TRANSPORT.md#the-refs-command) for the `refs` command; task: [PROGRESS.md](PROGRESS.md#s3-02--compare-mitigations); Sprint 2 limits: [TRANSPORT_RESULTS.md](TRANSPORT_RESULTS.md); S3-01 workload: [END_TO_END_RESULTS.md](END_TO_END_RESULTS.md)). This document covers all three of S3-02's mitigations, each in its own section: the first two, smaller claim sets, measured with the `claims` command, and cookie splitting, measured with the `cookies` command, and the third, reference tokens, measured with the `refs` command:

- **Smaller claim sets:** covered below.
- **Cookie splitting:** covered below. Splitting a token into `jwt.<index>.<count>` cookies of at most 4,000 characters gets every configuration under Chromium's 4,096-byte cookie limit, but cookie splitting does not get past the limits on the whole token: nginx's 8,192-byte `Cookie` header line, which still carries every chunk, nginx's response buffer for the `Set-Cookie` headers, and Chromium's 180 cookies per domain.
- **Reference tokens:** covered below. A 47-byte reference token in place of the JWT got every configuration, and SLH-DSA-SHA2-128f tokens of up to 300,000 bytes, through Chromium, nginx, and waitress at the documented defaults, as a cookie and as a Bearer header, but the application could not verify a reference without its reference store: with the store stopped, every reference got 503, and the lookup cost 0.125–0.178 ms per request from a separate store process over loopback (http.client, concurrency 1).

## Smaller claim sets

The question: how much does each configuration's token shrink when it carries only essential claims, and does that move any Sprint 2 size limit? The answer from this run:

- **Size:** every token shrinks by the same 641 bytes, from the 22-claim OpenID Connect fixture to its 5 required claims. That is 53.2% of RS256's token, 67.6% of ES256's and EdDSA's, 15.7% of ML-DSA-44's, and only 5.6% and 2.7% of SLH-DSA-SHA2-128s's and SLH-DSA-SHA2-128f's.
- **Limits:** exactly one verdict moves. ML-DSA-44's cookie goes from 4,095 to 3,454 bytes, under Chromium's 4,096-byte cookie name + value limit and under WSL2's nginx response buffer, so the browser that rejected it with OIDC claims now stores and sends it. Nothing moves for Bearer headers or for SLH-DSA, whose header and signature alone exceed every default limit.
- **Latency:** over loopback, the smaller payload saves 0.022–0.025 ms per request for the classical configurations and 0.014 ms for ML-DSA-44 from http.client at concurrency 1, most of it in verification. The SLH-DSA differences, every difference at concurrency 4, and the Chromium differences cannot be told apart from noise and the fixed run order. On a real uplink, the calculated saving is 0.051–5.128 ms per request for every configuration.

Every number below comes from one run on the team's Mac (Apple M5 Pro, 18 cores, macOS 26.5.1, arm64, 16 KiB memory pages; Python 3.15.2, Playwright 1.64.1, Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2 with its default 4 threads), recorded with `make claims` on November 18, 2026 (UTC; just after midnight local time) at commit `df91e2e`, with no uncommitted change to `scripts/` or `fixtures/`. Every token was signed with **ephemeral experiment keys, not production credentials**: each key was generated in memory for the run and discarded, so the tokens in its logs are not credentials either.

| Machine | Run | Files |
| --- | --- | --- |
| Apple M5 Pro (macOS) | [`20261118T053507Z-macos`](claims/20261118T053507Z-macos/) | [claims.json](claims/20261118T053507Z-macos/claims.json) |

| Phase | Evidence |
| --- | --- |
| Size limits, at the documented defaults | [nginx.conf](claims/20261118T053507Z-macos/limits/nginx.conf), [app.log.gz](claims/20261118T053507Z-macos/limits/logs/app.log.gz), [browser.log.gz](claims/20261118T053507Z-macos/limits/logs/browser.log.gz), [proxy-access.log.gz](claims/20261118T053507Z-macos/limits/logs/proxy-access.log.gz), [proxy-error.log.gz](claims/20261118T053507Z-macos/limits/logs/proxy-error.log.gz) |
| Latency, OIDC claims | [load.json](claims/20261118T053507Z-macos/latency-oidc/load.json), [raw.csv.gz](claims/20261118T053507Z-macos/latency-oidc/raw.csv.gz), [logs](claims/20261118T053507Z-macos/latency-oidc/logs/), [nginx.conf](claims/20261118T053507Z-macos/latency-oidc/nginx.conf) |
| Latency, essential claims | [load.json](claims/20261118T053507Z-macos/latency-essential/load.json), [raw.csv.gz](claims/20261118T053507Z-macos/latency-essential/raw.csv.gz), [logs](claims/20261118T053507Z-macos/latency-essential/logs/), [nginx.conf](claims/20261118T053507Z-macos/latency-essential/nginx.conf) |
| Sprint 2 boundaries (WSL2, committed earlier) | [cookie-default/sweep.json](transport/20261113T074114Z-wsl2/cookie-default/sweep.json), [cookie-16k/sweep.json](transport/20261113T074114Z-wsl2/cookie-16k/sweep.json), [bearer-default/sweep.json](transport/20261113T074114Z-wsl2/bearer-default/sweep.json) |

`claims.json` holds the settings, the environment, the claim sets, the token sizes, the derived Sprint 2 verdicts, every size-limit pair with its evidence and nonces, and the latency comparison; each latency directory is exactly what `load --output-dir` writes. The logs are gzip-compressed (`gzip -dc`). `claims.json`, both `load.json` and `raw.csv.gz` files, and every `app.log.gz` and `proxy-access.log.gz` hold no token. The size-limits phase's `browser.log.gz` holds the tokens Chromium sent and received, and its `proxy-error.log.gz` holds nginx's own truncated prefix of each of the four rejected Bearer header lines.

**Machine state.** Nothing else from the project was running: no other stack, load run, or test suite, and the `make serve` stack from the main checkout had been stopped (nothing listened on ports 8080 or 8081). When the run started, 0 sockets were in TIME_WAIT and the 1-minute load average was 2.2 on 18 cores. Spotify and Steam were open. This run replaces a provisional one recorded a few hours earlier, while the other S3-02 candidates' work and an idle `make serve` stack were on the same Mac.

### Claim sets

| Claim set | Fixture | Claims | Payload bytes |
| --- | --- | ---: | ---: |
| `minimal` (Sprint 1, a floor) | [fixtures/claims.json](../fixtures/claims.json) | 3 | 63 |
| `oidc` (typical OpenID Connect ID token) | [fixtures/claims_oidc.json](../fixtures/claims_oidc.json) | 22 | 618 |
| `essential` | [fixtures/claims_essential.json](../fixtures/claims_essential.json) | 5 | 137 |

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

**cookie-default: 3,915 bytes** (nginx's 4 KiB response buffer on WSL2, which the `Set-Cookie` response header block must fit; [sweep.json](transport/20261113T074114Z-wsl2/cookie-default/sweep.json))

| Configuration | OIDC token | OIDC headroom | OIDC fits | Essential token | Essential headroom | Essential fits | Moved |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| RS256 | 1,204 | +2,711 | yes | 563 | +3,352 | yes | no |
| ES256 | 948 | +2,967 | yes | 307 | +3,608 | yes | no |
| EdDSA | 948 | +2,967 | yes | 307 | +3,608 | yes | no |
| ML-DSA-44 | 4,095 | -180 | no | 3,454 | +461 | yes | **yes** |
| SLH-DSA-SHA2-128s | 11,353 | -7,438 | no | 10,712 | -6,797 | no | no |
| SLH-DSA-SHA2-128f | 23,662 | -19,747 | no | 23,021 | -19,106 | no | no |

**cookie-16k: 4,093 bytes** (Chromium's 4,096 bytes of cookie name + value, reached once nginx's buffers are raised to the Mac's 16k; [sweep.json](transport/20261113T074114Z-wsl2/cookie-16k/sweep.json))

| Configuration | OIDC token | OIDC headroom | OIDC fits | Essential token | Essential headroom | Essential fits | Moved |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| RS256 | 1,204 | +2,889 | yes | 563 | +3,530 | yes | no |
| ES256 | 948 | +3,145 | yes | 307 | +3,786 | yes | no |
| EdDSA | 948 | +3,145 | yes | 307 | +3,786 | yes | no |
| ML-DSA-44 | 4,095 | -2 | no | 3,454 | +639 | yes | **yes** |
| SLH-DSA-SHA2-128s | 11,353 | -7,260 | no | 10,712 | -6,619 | no | no |
| SLH-DSA-SHA2-128f | 23,662 | -19,569 | no | 23,021 | -18,928 | no | no |

**bearer-default: 8,168 bytes** (nginx's 8,192-byte request header line, `large_client_header_buffers 4 8k`; [sweep.json](transport/20261113T074114Z-wsl2/bearer-default/sweep.json))

| Configuration | OIDC token | OIDC headroom | OIDC fits | Essential token | Essential headroom | Essential fits | Moved |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| RS256 | 1,204 | +6,964 | yes | 563 | +7,605 | yes | no |
| ES256 | 948 | +7,220 | yes | 307 | +7,861 | yes | no |
| EdDSA | 948 | +7,220 | yes | 307 | +7,861 | yes | no |
| ML-DSA-44 | 4,095 | +4,073 | yes | 3,454 | +4,714 | yes | no |
| SLH-DSA-SHA2-128s | 11,353 | -3,185 | no | 10,712 | -2,544 | no | no |
| SLH-DSA-SHA2-128f | 23,662 | -15,494 | no | 23,021 | -14,853 | no | no |

**Measured on this Mac at the documented default limits.** One stack with no raised limit (its [nginx.conf](claims/20261118T053507Z-macos/limits/nginx.conf) has no `Not a default` line) and headless Chromium sent each configuration's OIDC and essential token once as a `jwt` cookie with production attributes (`Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600`) and once as an `Authorization: Bearer` header, and named the rejecting layer of each rejected pair from every layer's log. Every one of the 24 tokens also verified when sent straight to the application.

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
- **Latency:** over loopback from http.client at concurrency 1, splitting cost 0.011 ms per request for SLH-DSA-SHA2-128s and 0.023 ms for SLH-DSA-SHA2-128f, while ML-DSA-44's +0.005 ms is within the 0.003–0.006 ms same-size noise; the application's own handling grew with the number of chunks, by 0.006–0.010 ms for 2–6 chunks, and the classical tokens, in one chunk, were 0.004–0.007 ms faster, which is drift between the two runs. The differences at concurrency 4, single-chunk tokens included, are not attributed to splitting (see [Latency](#latency-1)). From Chromium only the classical tokens can be compared, because Chromium refuses every post-quantum single cookie, while split it delivered all six. The calculated network cost is 4–54 more request bytes, at most 0.432 ms on a 1 Mbit/s uplink.

Every number below comes from one run on the team's Mac (Apple M5 Pro, 18 cores, macOS 26.5.1, arm64, 16 KiB memory pages; Python 3.15.2, Playwright 1.64.1, Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2 with its default 4 threads), recorded with `make cookies` on November 18, 2026 (UTC, 17:44–17:46; 12:44 p.m. local time) at commit `6f6c3e6`, with no uncommitted change to `scripts/` or `fixtures/`. Every token was signed with **ephemeral experiment keys, not production credentials**: each key was generated in memory by the run's applications and discarded, so the tokens and chunks in its browser logs are not credentials either. Calculated figures are labeled as such; everything else was measured.

| Machine | Run | Files |
| --- | --- | --- |
| Apple M5 Pro (macOS) | [`20261118T174416Z-macos`](cookies/20261118T174416Z-macos/) | [cookies.json](cookies/20261118T174416Z-macos/cookies.json) |

| Phase | Evidence |
| --- | --- |
| Size limits and boundary, at the documented defaults | [nginx.conf](cookies/20261118T174416Z-macos/limits-default/nginx.conf), [app.log.gz](cookies/20261118T174416Z-macos/limits-default/logs/app.log.gz), [browser.log.gz](cookies/20261118T174416Z-macos/limits-default/logs/browser.log.gz), [proxy-access.log.gz](cookies/20261118T174416Z-macos/limits-default/logs/proxy-access.log.gz), [proxy-error.log.gz](cookies/20261118T174416Z-macos/limits-default/logs/proxy-error.log.gz) |
| Size limits, probes, and chunk handling, with raised buffers | [nginx.conf](cookies/20261118T174416Z-macos/limits-raised/nginx.conf), [app.log.gz](cookies/20261118T174416Z-macos/limits-raised/logs/app.log.gz), [browser.log.gz](cookies/20261118T174416Z-macos/limits-raised/logs/browser.log.gz), [proxy-access.log.gz](cookies/20261118T174416Z-macos/limits-raised/logs/proxy-access.log.gz), [proxy-error.log.gz](cookies/20261118T174416Z-macos/limits-raised/logs/proxy-error.log.gz) |
| Latency, one `jwt` cookie | [load.json](cookies/20261118T174416Z-macos/latency-cookie/load.json), [raw.csv.gz](cookies/20261118T174416Z-macos/latency-cookie/raw.csv.gz), [logs](cookies/20261118T174416Z-macos/latency-cookie/logs/), [nginx.conf](cookies/20261118T174416Z-macos/latency-cookie/nginx.conf) |
| Latency, split cookies | [load.json](cookies/20261118T174416Z-macos/latency-split/load.json), [raw.csv.gz](cookies/20261118T174416Z-macos/latency-split/raw.csv.gz), [logs](cookies/20261118T174416Z-macos/latency-split/logs/), [nginx.conf](cookies/20261118T174416Z-macos/latency-split/nginx.conf) |

`cookies.json` holds the settings, the environment, the chunk format and plan, every size-limit pair, boundary probe, and probe with its bytes, evidence, and nonces, the chunk-handling cases, and the latency comparison; each latency directory is exactly what `load --output-dir` writes. The logs are gzip-compressed (`gzip -dc`). `cookies.json`, both `load.json` and `raw.csv.gz` files, and every `app.log.gz` and `proxy-access.log.gz` hold no token, chunk, or cookie value. The two size-limit phases' `browser.log.gz` files hold the tokens and chunks Chromium sent, received, and stored, and `limits-default/logs/proxy-error.log.gz` holds nginx's own truncated prefix of each rejected `Cookie` line.

**Machine state.** Nothing else from the project was running: no other stack, load run, or test suite, and the `make serve` stack from the main checkout was not running (nothing listened on ports 8080 or 8081). When the run started (17:44:16 UTC), 0 sockets were in TIME_WAIT and the 1-minute load average was 1.3 on 18 cores; it was 3.9 at the end, including the run's own load. Spotify and Steam were open. This run replaces a provisional one recorded earlier the same day, while the other S3-02 candidates were being built and tested on the same Mac.

### Format

The application ([scripts/transport_app.py](../scripts/transport_app.py), [Token endpoints](TRANSPORT.md#token-endpoints)) issues a split with `GET /api/token/issue?alg=<name>&delivery=split`, one `Set-Cookie` header per chunk:

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

**At the documented defaults** (stack `limits-default`; its [nginx.conf](cookies/20261118T174416Z-macos/limits-default/nginx.conf) has no `Not a default` line: `large_client_header_buffers 4 8k`, and a 16 KiB `proxy_buffer_size`, one memory page):

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

**With nginx's buffers raised** (stack `limits-raised`; its [nginx.conf](cookies/20261118T174416Z-macos/limits-raised/nginx.conf) marks `--header-buffers 32k`, `large_client_header_buffers 4 32k`, and `--proxy-buffers 32k`, `proxy_buffer_size 32k; proxy_buffers 8 32k`, as not defaults):

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

The S3-01 workload ([END_TO_END_RESULTS.md](END_TO_END_RESULTS.md#workload)) ran twice, first with one `jwt` cookie and then with split cookies, each on a new stack: a closed loop of `GET /api/token/verify?timing=1&nonce=<32 hex digits>` requests with OIDC tokens, from http.client threads and from Chromium's test page, at concurrency 1 and 4, with 1 second of warm-up and 2 seconds measured per cell, `--header-buffers 32k`, `--proxy-buffers 32k`, and `--upstream-keepalive 64`. Size-control cells were off. Each cell's token was issued with the default attributes, as in S3-01. The single cookie is the baseline, not a Bearer header, so the comparison isolates the cost of splitting; Bearer comparisons are in [END_TO_END_RESULTS.md](END_TO_END_RESULTS.md). Every measured request verified: 144,292 with one cookie and 167,165 split, none failed, and every delivered cell had at least 2,162 verified requests. Chromium refused the single cookie of ML-DSA-44 and both SLH-DSA tokens, so those six browser cells of the cookie run were not delivered and sent no request.

Latency is the client-measured time from sending a request to reading its whole response body, in milliseconds; p95 is nearest-rank. The difference is the split mean minus the single-cookie mean, so a positive difference means splitting was slower. Chromium coarsens its timer to about 0.1 ms, so its medians and p95 values are multiples of 0.1 ms.

**http.client (direct), concurrency 1**

| Configuration | Token | Chunks | Cookie mean | Split mean | Difference | Cookie median | Split median | Cookie p95 | Split p95 | Cookie req/s | Split req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 0.209 | 0.204 | -0.004 | 0.206 | 0.202 | 0.225 | 0.220 | 4,771 | 4,870 |
| ES256 | 948 | 1 | 0.224 | 0.219 | -0.005 | 0.221 | 0.217 | 0.243 | 0.232 | 4,446 | 4,541 |
| EdDSA | 948 | 1 | 0.230 | 0.223 | -0.007 | 0.220 | 0.221 | 0.272 | 0.236 | 4,333 | 4,470 |
| ML-DSA-44 | 4,095 | 2 | 0.233 | 0.239 | +0.005 | 0.231 | 0.238 | 0.249 | 0.252 | 4,265 | 4,169 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | 0.408 | 0.418 | +0.011 | 0.406 | 0.416 | 0.424 | 0.433 | 2,446 | 2,383 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | 0.700 | 0.724 | +0.023 | 0.698 | 0.720 | 0.722 | 0.739 | 1,425 | 1,380 |

**http.client (direct), concurrency 4**

| Configuration | Token | Chunks | Cookie mean | Split mean | Difference | Cookie median | Split median | Cookie p95 | Split p95 | Cookie req/s | Split req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 0.647 | 0.663 | +0.016 | 0.623 | 0.640 | 0.965 | 0.971 | 6,171 | 6,023 |
| ES256 | 948 | 1 | 0.630 | 0.646 | +0.016 | 0.610 | 0.624 | 0.922 | 0.940 | 6,337 | 6,184 |
| EdDSA | 948 | 1 | 0.621 | 0.640 | +0.019 | 0.599 | 0.620 | 0.920 | 0.933 | 6,429 | 6,238 |
| ML-DSA-44 | 4,095 | 2 | 0.572 | 0.614 | +0.042 | 0.550 | 0.582 | 0.839 | 0.884 | 6,977 | 6,497 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | 1.134 | 1.163 | +0.028 | 1.108 | 1.139 | 1.652 | 1.673 | 3,522 | 3,435 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | 2.149 | 2.185 | +0.036 | 2.120 | 2.164 | 3.124 | 3.169 | 1,860 | 1,829 |

**Chromium (browser), concurrency 1**

| Configuration | Token | Chunks | Cookie mean | Split mean | Difference | Cookie median | Split median | Cookie p95 | Split p95 | Cookie req/s | Split req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 0.421 | 0.439 | +0.017 | 0.400 | 0.400 | 0.500 | 0.500 | 2,373 | 2,279 |
| ES256 | 948 | 1 | 0.479 | 0.549 | +0.070 | 0.500 | 0.500 | 0.600 | 1.000 | 2,086 | 1,820 |
| EdDSA | 948 | 1 | 0.450 | 0.505 | +0.055 | 0.400 | 0.500 | 0.500 | 0.700 | 2,219 | 1,979 |
| ML-DSA-44 | 4,095 | 2 | not delivered | 0.487 | — | — | 0.500 | — | 0.600 | — | 2,050 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | not delivered | 0.621 | — | — | 0.600 | — | 0.700 | — | 1,610 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | not delivered | 0.925 | — | — | 0.900 | — | 1.000 | — | 1,081 |

**Chromium (browser), concurrency 4**

| Configuration | Token | Chunks | Cookie mean | Split mean | Difference | Cookie median | Split median | Cookie p95 | Split p95 | Cookie req/s | Split req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 1 | 0.964 | 0.990 | +0.025 | 0.900 | 0.900 | 1.400 | 1.400 | 4,146 | 4,040 |
| ES256 | 948 | 1 | 0.965 | 0.990 | +0.025 | 0.900 | 0.900 | 1.300 | 1.300 | 4,142 | 4,039 |
| EdDSA | 948 | 1 | 0.962 | 0.973 | +0.011 | 0.900 | 0.900 | 1.300 | 1.300 | 4,154 | 4,109 |
| ML-DSA-44 | 4,095 | 2 | not delivered | 0.955 | — | — | 0.900 | — | 1.300 | — | 4,185 |
| SLH-DSA-SHA2-128s | 11,353 | 3 | not delivered | 1.480 | — | — | 1.400 | — | 2.100 | — | 2,700 |
| SLH-DSA-SHA2-128f | 23,662 | 6 | not delivered | 2.455 | — | — | 2.400 | — | 3.600 | — | 1,628 |

**Noise level.** EdDSA and ES256 tokens are the same size, so the difference between their means shows how much two cells differ without any change in size. With one cookie it is +0.006 ms from http.client at concurrency 1 and -0.009 ms at concurrency 4, and -0.028 and -0.003 ms from Chromium; split, +0.003 and -0.006 ms from http.client and -0.044 and -0.017 ms from Chromium. This measures noise within one run only; the two runs ran one after the other, always the single cookie first, so a drift between them affects every configuration's difference alike.

Where the difference is clearest, http.client at concurrency 1, the components show where it comes from (difference of each component's mean, split minus single cookie, in ms):

| Configuration | Chunks | Total | Transfer | Other handling | Verification |
| --- | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1 | -0.004 | -0.008 | +0.004 | -0.000 |
| ES256 | 1 | -0.005 | -0.008 | +0.004 | -0.001 |
| EdDSA | 1 | -0.007 | -0.008 | +0.004 | -0.003 |
| ML-DSA-44 | 2 | +0.005 | +0.001 | +0.006 | -0.001 |
| SLH-DSA-SHA2-128s | 3 | +0.011 | +0.000 | +0.006 | +0.004 |
| SLH-DSA-SHA2-128f | 6 | +0.023 | +0.002 | +0.010 | +0.011 |

- **http.client, concurrency 1:** other handling, the verify handler outside `verify_token`, grows with the number of chunks: 0.004 ms for one chunk, 0.006 ms for two and for three, and 0.010 ms for six. That is consistent with the work splitting adds by design, the application parsing the chunk cookies and joining them. Transfer is 0.008 ms lower in the split run for the single-chunk classical tokens, which no size difference explains (the split request is 4 bytes longer), so it is drift between the two runs; for the post-quantum tokens it is within 0.002 ms. ML-DSA-44's total difference, +0.005 ms, is within the noise level, and the classical configurations' -0.004 to -0.007 ms is the same drift. SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f are 0.011 and 0.023 ms slower split, mostly in other handling; SLH-DSA-SHA2-128f's +0.011 ms of verification is not caused by splitting, since `verify_token` gets the same token either way, and is part of the run-to-run variation.
- **http.client, concurrency 4:** every configuration was slower split: the single-chunk classical tokens by 0.016–0.019 ms, ML-DSA-44 by 0.042 ms, and SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128f by 0.028 and 0.036 ms, against same-size noise of 0.006–0.009 ms. The single-chunk requests differ only by a 4-byte longer cookie name, so at least that much is drift between the two runs, which always ran the single cookie first; these differences are reported as measured and not attributed to splitting.
- **Chromium:** only the classical configurations can be compared. They were 0.011–0.070 ms slower split, against same-size noise of up to 0.044 ms and a 0.1 ms timer; their requests differ only by a 4-byte name, so this is drift between the runs, not an effect of splitting. For the post-quantum configurations splitting is the difference between no request at all and a working cookie: split, Chromium sent ML-DSA-44's token at 0.487 ms per request at concurrency 1, close to the classical tokens' 0.439–0.549 ms.

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
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py cookies --settings results/cookies/20261118T174416Z-macos/cookies.json --output-dir results/cookies/<YYYYMMDDTHHMMSSZ>-macos
# one latency run alone, from its saved load.json:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --settings results/cookies/20261118T174416Z-macos/latency-split/load.json --output-dir /tmp/latency-split
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
latency  direct  c=1   RS256               1,204 B x1  mean 0.209 -> 0.204 ms (-0.004)  median 0.206 -> 0.202  p95 0.225 -> 0.220  4,770.8 -> 4,870.2 req/s
latency  direct  c=1   ES256                 948 B x1  mean 0.224 -> 0.219 ms (-0.005)  median 0.221 -> 0.217  p95 0.243 -> 0.232  4,446.0 -> 4,541.2 req/s
latency  direct  c=1   EdDSA                 948 B x1  mean 0.230 -> 0.223 ms (-0.007)  median 0.220 -> 0.221  p95 0.272 -> 0.236  4,332.7 -> 4,470.4 req/s
latency  direct  c=1   ML-DSA-44           4,095 B x2  mean 0.233 -> 0.239 ms (+0.005)  median 0.231 -> 0.238  p95 0.249 -> 0.252  4,265.5 -> 4,168.9 req/s
latency  direct  c=1   SLH-DSA-SHA2-128s  11,353 B x3  mean 0.408 -> 0.418 ms (+0.011)  median 0.406 -> 0.416  p95 0.424 -> 0.433  2,445.5 -> 2,383.3 req/s
latency  direct  c=1   SLH-DSA-SHA2-128f  23,662 B x6  mean 0.700 -> 0.724 ms (+0.023)  median 0.698 -> 0.720  p95 0.722 -> 0.739  1,425.5 -> 1,379.8 req/s
latency  direct  c=4   RS256               1,204 B x1  mean 0.647 -> 0.663 ms (+0.016)  median 0.623 -> 0.640  p95 0.965 -> 0.971  6,171.3 -> 6,023.1 req/s
latency  direct  c=4   ES256                 948 B x1  mean 0.630 -> 0.646 ms (+0.016)  median 0.610 -> 0.624  p95 0.922 -> 0.940  6,337.3 -> 6,184.0 req/s
latency  direct  c=4   EdDSA                 948 B x1  mean 0.621 -> 0.640 ms (+0.019)  median 0.599 -> 0.620  p95 0.920 -> 0.933  6,429.5 -> 6,238.2 req/s
latency  direct  c=4   ML-DSA-44           4,095 B x2  mean 0.572 -> 0.614 ms (+0.042)  median 0.550 -> 0.582  p95 0.839 -> 0.884  6,976.6 -> 6,496.9 req/s
latency  direct  c=4   SLH-DSA-SHA2-128s  11,353 B x3  mean 1.134 -> 1.163 ms (+0.028)  median 1.108 -> 1.139  p95 1.652 -> 1.673  3,522.1 -> 3,435.5 req/s
latency  direct  c=4   SLH-DSA-SHA2-128f  23,662 B x6  mean 2.149 -> 2.185 ms (+0.036)  median 2.120 -> 2.164  p95 3.124 -> 3.169  1,859.6 -> 1,828.6 req/s
latency  browser c=1   RS256               1,204 B x1  mean 0.421 -> 0.439 ms (+0.017)  median 0.400 -> 0.400  p95 0.500 -> 0.500  2,372.6 -> 2,278.7 req/s
latency  browser c=1   ES256                 948 B x1  mean 0.479 -> 0.549 ms (+0.070)  median 0.500 -> 0.500  p95 0.600 -> 1.000  2,086.4 -> 1,819.9 req/s
latency  browser c=1   EdDSA                 948 B x1  mean 0.450 -> 0.505 ms (+0.055)  median 0.400 -> 0.500  p95 0.500 -> 0.700  2,219.0 -> 1,978.7 req/s
latency  browser c=1   ML-DSA-44           4,095 B x2  no verified request: cookie not delivered
latency  browser c=1   SLH-DSA-SHA2-128s  11,353 B x3  no verified request: cookie not delivered
latency  browser c=1   SLH-DSA-SHA2-128f  23,662 B x6  no verified request: cookie not delivered
latency  browser c=4   RS256               1,204 B x1  mean 0.964 -> 0.990 ms (+0.025)  median 0.900 -> 0.900  p95 1.400 -> 1.400  4,146.0 -> 4,039.6 req/s
latency  browser c=4   ES256                 948 B x1  mean 0.965 -> 0.990 ms (+0.025)  median 0.900 -> 0.900  p95 1.300 -> 1.300  4,141.6 -> 4,039.1 req/s
latency  browser c=4   EdDSA                 948 B x1  mean 0.962 -> 0.973 ms (+0.011)  median 0.900 -> 0.900  p95 1.300 -> 1.300  4,154.3 -> 4,109.0 req/s
latency  browser c=4   ML-DSA-44           4,095 B x2  no verified request: cookie not delivered
latency  browser c=4   SLH-DSA-SHA2-128s  11,353 B x3  no verified request: cookie not delivered
latency  browser c=4   SLH-DSA-SHA2-128f  23,662 B x6  no verified request: cookie not delivered
Saved the results to results/cookies/20261118T174416Z-macos
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
- **Machine state.** Nothing else from the project was running, but Spotify and Steam were open. The 1-minute load average was 1.3 when the run started and 3.9 when it ended, including the run's own load.

## Reference tokens

The question: if the application sends a short opaque reference instead of the signed JWT and looks the JWT up on the server, which size limits does it still run into, what does the lookup cost in latency, and what does the design give up? The answer from this run:

- **Size:** a reference is 47 bytes whatever the token, so its `Cookie` line is 65 bytes, its `Authorization: Bearer` line 71 bytes, and its `Set-Cookie` line with production attributes 126 bytes (calculated), against 962–23,676, 972–23,686, and 1,023–23,737 bytes for the JWTs. The application received the same 608 bytes of request headers for every cookie-carried reference from Chromium, and 614 for every Bearer one, from ES256's 948-byte token to a 300,000-byte one (measured).
- **Limits:** at the documented defaults every reference verified, browser → nginx → waitress, as a `jwt_ref` cookie and as a Bearer header, for all six configurations and for SLH-DSA-SHA2-128f tokens padded to 65,536 and 300,000 bytes; the second is beyond waitress's 262,144-byte header limit, the last limit Sprint 2 found. Compared with the JWT verdicts derived from the committed claims run, five of the twelve pairs moved from rejected to verified: ML-DSA-44's cookie and both SLH-DSA configurations in both carriers.
- **Handling:** every case got the status the application's rules give it. Unknown, expired, and revoked references got 401 after the lookup and before any verification, and a malformed `jwt_ref` cookie 401 without a lookup; two references, or a reference with a JWT, got 400. Revocation took effect on the next request. A reference sent as a `jwt` cookie got 401, because it carries no claims or signature.
- **What it gives up:** once the store process was stopped, every reference got 503 and no new reference could be issued, while a Bearer JWT still verified on the same stack (see [What the design gives up](#what-the-design-gives-up)).
- **Latency:** over loopback from http.client at concurrency 1, the lookup took 0.001 ms in the application's own memory and 0.125–0.178 ms in the separate store process, growing with the token the store sends back. With the memory store, Bearer references were 0.039, 0.083, and 0.168 ms faster than Bearer JWTs for ML-DSA-44, SLH-DSA-SHA2-128s, and SLH-DSA-SHA2-128f, almost all of it transfer, and 0.010 ms faster for the classical ones. With the remote store they were 0.127–0.131 ms slower for the classical configurations, 0.101 and 0.082 ms slower for ML-DSA-44 and SLH-DSA-SHA2-128s, and only 0.001 ms slower for SLH-DSA-SHA2-128f, whose shorter request paid for the lookup. At concurrency 4 the remote lookups queued, at 0.312–0.900 ms. The calculated network saving is 901–23,615 request bytes, up to 288.920 ms per request on a 1 Mbit/s uplink.

Every number below comes from one run on the team's Mac (Apple M5 Pro, 18 cores, macOS 26.5.1, arm64, 16 KiB memory pages; Python 3.15.2, Playwright 1.64.1, Chromium 156.0.8078.4, nginx 1.31.8, waitress 3.0.2 with its default 4 threads), recorded with `make refs` on November 19, 2026 (UTC, 05:11–05:16; 12:11 a.m. local time) at commit `a035e7c`, with no uncommitted change to `scripts/` or `fixtures/`. Every token was signed with **ephemeral experiment keys, not production credentials**: each key was generated in memory by the run's applications and discarded. Every reference is 32 random bytes that named a token only in the memory of its stack's application or store process, so the references in the size-limits browser log are meaningless now that those stacks have stopped. Calculated and derived figures are labeled as such; everything else was measured.

| Machine | Run | Files |
| --- | --- | --- |
| Apple M5 Pro (macOS) | [`20261119T051144Z-macos`](refs/20261119T051144Z-macos/) | [refs.json](refs/20261119T051144Z-macos/refs.json) |

| Phase | Evidence |
| --- | --- |
| Size limits and probes, at the documented defaults, memory store | [nginx.conf](refs/20261119T051144Z-macos/limits/nginx.conf), [app.log.gz](refs/20261119T051144Z-macos/limits/logs/app.log.gz), [browser.log.gz](refs/20261119T051144Z-macos/limits/logs/browser.log.gz), [proxy-access.log.gz](refs/20261119T051144Z-macos/limits/logs/proxy-access.log.gz), [proxy-error.log.gz](refs/20261119T051144Z-macos/limits/logs/proxy-error.log.gz) |
| Reference handling, remote store | [nginx.conf](refs/20261119T051144Z-macos/behavior/nginx.conf), [app.log.gz](refs/20261119T051144Z-macos/behavior/logs/app.log.gz), [proxy-access.log.gz](refs/20261119T051144Z-macos/behavior/logs/proxy-access.log.gz), [proxy-error.log.gz](refs/20261119T051144Z-macos/behavior/logs/proxy-error.log.gz), [store.log.gz](refs/20261119T051144Z-macos/behavior/logs/store.log.gz) |
| Latency, Bearer JWTs | [load.json](refs/20261119T051144Z-macos/latency-jwt/load.json), [raw.csv.gz](refs/20261119T051144Z-macos/latency-jwt/raw.csv.gz), [app.log.gz](refs/20261119T051144Z-macos/latency-jwt/logs/app.log.gz), [browser.log.gz](refs/20261119T051144Z-macos/latency-jwt/logs/browser.log.gz), [proxy-access.log.gz](refs/20261119T051144Z-macos/latency-jwt/logs/proxy-access.log.gz), [proxy-error.log.gz](refs/20261119T051144Z-macos/latency-jwt/logs/proxy-error.log.gz), [nginx.conf](refs/20261119T051144Z-macos/latency-jwt/nginx.conf) |
| Latency, Bearer references, memory store | [load.json](refs/20261119T051144Z-macos/latency-ref-memory/load.json), [raw.csv.gz](refs/20261119T051144Z-macos/latency-ref-memory/raw.csv.gz), [app.log.gz](refs/20261119T051144Z-macos/latency-ref-memory/logs/app.log.gz), [browser.log.gz](refs/20261119T051144Z-macos/latency-ref-memory/logs/browser.log.gz), [proxy-access.log.gz](refs/20261119T051144Z-macos/latency-ref-memory/logs/proxy-access.log.gz), [proxy-error.log.gz](refs/20261119T051144Z-macos/latency-ref-memory/logs/proxy-error.log.gz), [nginx.conf](refs/20261119T051144Z-macos/latency-ref-memory/nginx.conf) |
| Latency, Bearer references, remote store | [load.json](refs/20261119T051144Z-macos/latency-ref-remote/load.json), [raw.csv.gz](refs/20261119T051144Z-macos/latency-ref-remote/raw.csv.gz), [app.log.gz](refs/20261119T051144Z-macos/latency-ref-remote/logs/app.log.gz), [browser.log.gz](refs/20261119T051144Z-macos/latency-ref-remote/logs/browser.log.gz), [proxy-access.log.gz](refs/20261119T051144Z-macos/latency-ref-remote/logs/proxy-access.log.gz), [proxy-error.log.gz](refs/20261119T051144Z-macos/latency-ref-remote/logs/proxy-error.log.gz), [store.log.gz](refs/20261119T051144Z-macos/latency-ref-remote/logs/store.log.gz), [nginx.conf](refs/20261119T051144Z-macos/latency-ref-remote/nginx.conf) |

`refs.json` holds the settings, the environment, the reference format, the plan, every size-limit pair and probe with its bytes, evidence, and nonces, the derived JWT verdicts, the handling cases, and the latency comparison; each latency directory is what `load --output-dir` writes. The logs are gzip-compressed (`gzip -dc`). `refs.json`, every `load.json` and `raw.csv.gz`, every `app.log.gz`, `proxy-access.log.gz`, `proxy-error.log.gz`, and `store.log.gz`, and the latency runs' `browser.log.gz` hold no token, reference, or cookie value. Only `limits/logs/browser.log.gz` holds references: the ones Chromium received, stored, and sent.

**Machine state.** Nothing else from the project was running: no other stack, load run, or test suite, and the `make serve` stack from the main checkout was not running (nothing listened on ports 8080 or 8081). When the run started (05:11:44 UTC), 1 socket was in TIME_WAIT and the 1-minute load average was 2.0 on 18 cores; at the end it was 5.1, including the run's own load, with 142 sockets in TIME_WAIT. Spotify, Steam, and Discord were closed. This run replaces a provisional one recorded while the other S3-02 candidates were being built and tested on the same Mac.

### Format

The application ([scripts/transport_app.py](../scripts/transport_app.py), [Token endpoints](TRANSPORT.md#token-endpoints)) issues a reference with `GET /api/token/reference?alg=<name>`, signs and verifies the token exactly as `/api/token/issue` does, and keeps it in its reference store:

| Property | Value |
| --- | --- |
| Reference | `ref_` and 43 base64url characters, `secrets.token_urlsafe(32)`: 32 random bytes, 47 bytes in all. It encodes nothing about the token or its claims, and it has no dot, so it is never mistaken for a JWT |
| Carriers | a `jwt_ref` cookie (`delivery=cookie`, source `ref_cookie`), or the JSON body (`delivery=body`) for an `Authorization: Bearer <reference>` header (source `ref_bearer`); any Bearer value that is not exactly a reference is a JWT, as before |
| Attributes | the size-limit pairs and probes use the production set `Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600` |
| Time to live | `ttl`, 3,600 seconds by default (the production cookie's `Max-Age`), at most 86,400 |
| Stores | `memory`: the application's own memory; `remote`: a separate waitress store process on `127.0.0.1`, reached over loopback HTTP/1.1 with one persistent connection per application thread. Both keep everything in memory |
| Verify | the token found is checked and verified exactly like a cookie or Bearer token; `ref.status` is `found`, `unknown`, `expired`, `revoked`, `malformed`, or `unavailable`, and `timing.lookup_ns` times the store's `get` |
| Revoke | `POST /api/token/revoke` with the reference; the store answers `revoked` for it from then on |

The application verifies the signature again after every lookup, as the phantom-token pattern does, so verification stays in the comparison and the lookup is its own component. The memory store gives a lookup with no network in it, a lower bound; the remote store, a separate process the application reaches over loopback HTTP, as it would reach a token service (RFC 7662 introspection, for example), gives a networked one.

### Size limits

**Calculated, not measured.** Each configuration's unpadded OIDC token (`token_sizing.token_bytes`) and a 47-byte reference, with the bytes each limit counts: a cookie's name + value (Chromium's 4,096 bytes), the `Cookie` and `Authorization: Bearer` lines the client sends (nginx's 8,192-byte header line), and the `Set-Cookie` line with production attributes (which must fit, with the other response headers, in nginx's `proxy_buffer_size`). Every line includes its CRLF.

| Configuration | Token | Reference | JWT cookie name + value | Reference cookie name + value | JWT Cookie line | Reference Cookie line | JWT Authorization line | Reference Authorization line | JWT Set-Cookie line | Reference Set-Cookie line |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 47 | 1,207 | 54 | 1,218 | 65 | 1,228 | 71 | 1,279 | 126 |
| ES256 | 948 | 47 | 951 | 54 | 962 | 65 | 972 | 71 | 1,023 | 126 |
| EdDSA | 948 | 47 | 951 | 54 | 962 | 65 | 972 | 71 | 1,023 | 126 |
| ML-DSA-44 | 4,095 | 47 | 4,098 | 54 | 4,109 | 65 | 4,119 | 71 | 4,170 | 126 |
| SLH-DSA-SHA2-128s | 11,353 | 47 | 11,356 | 54 | 11,367 | 65 | 11,377 | 71 | 11,428 | 126 |
| SLH-DSA-SHA2-128f | 23,662 | 47 | 23,665 | 54 | 23,676 | 65 | 23,686 | 71 | 23,737 | 126 |

Against the documented limits (calculated): every reference fits all three, while ML-DSA-44's JWT is over the 4,096-byte cookie limit and both SLH-DSA JWTs are over the cookie limit and nginx's 8,192-byte line in both carriers.

**Measured at the documented defaults** (stack `limits`, memory store; its [nginx.conf](refs/20261119T051144Z-macos/limits/nginx.conf) has no `Not a default` line: `large_client_header_buffers 4 8k`, and a 16 KiB `proxy_buffer_size`, one memory page). For each configuration and carrier, a new Chromium context loaded the test page through nginx, `fetch()`ed `/api/token/reference` with OIDC claims and production attributes, read its cookie jar, and `fetch()`ed `/api/token/verify` with the stored `jwt_ref` cookie or an `Authorization: Bearer <reference>` header. The JWT column is **derived, not measured**: it is the outcome the committed claims run measured on this Mac for the same OIDC token and carrier at the same defaults ([results/claims/20261118T053507Z-macos/claims.json](claims/20261118T053507Z-macos/claims.json), `limits.jwt` in `refs.json`), so this run sent no JWT that nginx would reject. A pair has **moved** when the JWT was rejected and the reference verified.

| Configuration | Carrier | Token | JWT, derived | Reference | Reference header line | Application received | Verified directly | Moved |
| --- | --- | ---: | --- | --- | ---: | ---: | --- | --- |
| RS256 | Cookie | 1,204 | verified | verified | 65 | 608 | yes | no |
| RS256 | Bearer | 1,204 | verified | verified | 71 | 614 | yes | no |
| ES256 | Cookie | 948 | verified | verified | 65 | 608 | yes | no |
| ES256 | Bearer | 948 | verified | verified | 71 | 614 | yes | no |
| EdDSA | Cookie | 948 | verified | verified | 65 | 608 | yes | no |
| EdDSA | Bearer | 948 | verified | verified | 71 | 614 | yes | no |
| ML-DSA-44 | Cookie | 4,095 | rejected by the browser | verified | 65 | 608 | yes | **yes** |
| ML-DSA-44 | Bearer | 4,095 | verified | verified | 71 | 614 | yes | no |
| SLH-DSA-SHA2-128s | Cookie | 11,353 | rejected by the browser | verified | 65 | 608 | yes | **yes** |
| SLH-DSA-SHA2-128s | Bearer | 11,353 | rejected by the proxy | verified | 71 | 614 | yes | **yes** |
| SLH-DSA-SHA2-128f | Cookie | 23,662 | rejected by the proxy | verified | 65 | 608 | yes | **yes** |
| SLH-DSA-SHA2-128f | Bearer | 23,662 | rejected by the proxy | verified | 71 | 614 | yes | **yes** |

The reference header line is calculated; "Application received" is `header_bytes` from the verify request's own `app.log` line, every header the application received from Chromium through nginx. "Verified directly" sends a reference issued straight from the application straight back to it with the same carrier. In the claims run, Chromium refused the ML-DSA-44 and SLH-DSA-SHA2-128s cookies (over 4,096 bytes of name + value), nginx answered 502 to SLH-DSA-SHA2-128f's `Set-Cookie` response (over its 16 KiB `proxy_buffer_size`), and nginx answered 400 to both SLH-DSA Bearer headers (over its 8,192-byte line). A reference meets none of those limits: its `Set-Cookie` header is 126 bytes and its request line 65 or 71.

**Probes.** On the same stack, SLH-DSA-SHA2-128f tokens with OIDC claims were padded to the largest pad whose token is at most each target, and their references sent as a cookie and as a Bearer header in the same way:

| Target | Pad | Token | Carrier | Reference | Outcome | Reference header line | Application received |
| ---: | ---: | ---: | --- | ---: | --- | ---: | ---: |
| 65,536 | 31,396 | 65,536 | Cookie | 47 | verified | 65 | 608 |
| 65,536 | 31,396 | 65,536 | Bearer | 47 | verified | 71 | 614 |
| 300,000 | 207,244 | 300,000 | Cookie | 47 | verified | 65 | 608 |
| 300,000 | 207,244 | 300,000 | Bearer | 47 | verified | 71 | 614 |

The 300,000-byte token is beyond waitress's 262,144-byte request header limit, the last limit Sprint 2 found: as a JWT it could not reach the application in any header, whatever nginx's buffers. As a reference it never travels: it stays in the store, and the request carries 47 bytes.

**A request size independent of the token.** `app_received_headers` was 608 bytes for every cookie-carried reference and 614 for every Bearer one, from ES256's 948-byte token to the 300,000-byte probe; the difference is `cookie: jwt_ref=<reference>` against `authorization: Bearer <reference>`. In the latency runs the same holds for http.client: 121 bytes of headers for every reference, against 1,022–23,736 bytes for the Bearer JWTs (`bytes.app_received_headers` in each `load.json`). The size limits no longer depend on the signature scheme; what depends on it now is the store, which holds the whole token.

### Reference handling

**Measured on the remote store.** A new stack with the store process and no raised limit (stack `behavior`). References A, B (`ttl=1`), and C to ML-DSA-44's 4,095-byte OIDC token, and the JWT J itself, were issued straight from the application with `delivery=body`. http.client then sent `GET /api/token/verify?timing=1&nonce=<32 hex digits>` through nginx with the cookies and headers below, in this order; before `store_unavailable` the run stopped the store process while nginx and the application kept running. "Lookup" means the store's `get` was called (`timing.lookup_ns` not null), and "Verify called" that the adapter's `verify_token` ran (`timing.verify_ns` not null).

| Case | Sent | Store | Status | Verified | Source | `ref.status` | Lookup | Verify called | Error |
| --- | --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| `cookie` | `jwt_ref` (A) | running | 200 | yes | ref_cookie | found | yes | yes | — |
| `bearer` | `Authorization: Bearer` (A) | running | 200 | yes | ref_bearer | found | yes | yes | — |
| `among_other_cookies` | `a`, `jwt_ref` (A), `theme` | running | 200 | yes | ref_cookie | found | yes | yes | — |
| `unknown` | `Authorization: Bearer` (a reference never stored) | running | 401 | no | ref_bearer | unknown | yes | no | unknown reference: the store holds no token for it |
| `malformed_cookie` | `jwt_ref` (`not-a-reference`) | running | 401 | no | ref_cookie | malformed | no | no | malformed reference: a jwt_ref cookie must hold ref_ and 43 base64url characters |
| `expired` | `Authorization: Bearer` (B, more than 1 s after its issue) | running | 401 | no | ref_bearer | expired | yes | no | expired reference: its time to live has passed |
| `revoked` | `Authorization: Bearer` (C, after `POST /api/token/revoke` with C got 200) | running | 401 | no | ref_bearer | revoked | yes | no | revoked reference: it was revoked |
| `two_references` | `jwt_ref` (A), `jwt_ref` (A) | running | 400 | no | null | — | no | no | more than one token: send one jwt_ref cookie or one Bearer reference alone, without another reference, a jwt cookie, chunk cookies, or a Bearer token |
| `reference_and_jwt` | `jwt_ref` (A), `Authorization: Bearer` (J) | running | 400 | no | null | — | no | no | more than one token (as above) |
| `reference_as_jwt` | `jwt` (A) | running | 401 | no | cookie | — | no | no | the token header has no readable alg naming one of RS256, ES256, EdDSA, ML-DSA-44, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f |
| `store_unavailable` | `Authorization: Bearer` (A) | stopped | 503 | no | ref_bearer | unavailable | yes | no | reference store unavailable |
| `jwt_without_store` | `Authorization: Bearer` (J) | stopped | 200 | yes | bearer | — | no | yes | — |
| `issue_without_store` | none: `GET /api/token/reference?alg=ML-DSA-44&delivery=cookie&claims=oidc` | stopped | 503 | no | null | — | no | no | reference store unavailable (as above); no `Set-Cookie` |

Every case got the status the application's rules give it. The store's own log ([store.log.gz](refs/20261119T051144Z-macos/behavior/logs/store.log.gz)) has one `POST /get` for each case with a lookup up to `revoked`, and the `POST /revoke` between `expired` and `revoked`; the reference itself travels only in the request body, so no log line holds it. In `store_unavailable`, the application's kept-alive connection to the stopped store failed, it reopened it once, and that was refused, so the lookup was timed and the answer was 503 rather than a 401 that would wrongly call the reference invalid.

### What the design gives up

- **Stateless verification.** A JWT is verified with the public key alone; a reference needs the store on every request. On the same stack, with nginx and the application running and only the store process stopped, the reference got 503 (`store_unavailable`) while the Bearer JWT still verified (`jwt_without_store`, 200), and no new reference could be issued (`issue_without_store`, 503). The store is now part of every authenticated request's availability, measured here only for a stopped store; a slow or partly failing store was not measured.
- **Offline and third-party verification.** The reference carries no claims or signature, only 32 random bytes (see [Format](#format-1)), so a party without the store learns nothing from it: sent as if it were a JWT, it got 401 because it has no readable header (`reference_as_jwt`), and a well-formed reference that the store does not hold is refused like any other (`unknown`). A JWT can be verified offline, or by another service, with the issuer's public key; this run does not show that, because the application never publishes its experiment public keys, so it is stated, not measured. Another service would have to call the store, or an introspection endpoint in front of it, to accept a reference.
- **Unknown, expired, and revoked references.** The store answers for each reference, so the application can refuse an unknown (`unknown`), expired (`expired`, after its 1-second time to live), or revoked (`revoked`) reference before it verifies anything, all with 401. Revocation is immediate: the request right after `POST /api/token/revoke` was refused. A JWT stays valid until its `exp` (or the application keeps its own deny list); `POST /api/token/revoke` refuses a JWT with 400, which this run did not measure. The experiment's stores keep expired and revoked entries to tell them apart from unknown ones (see Limitations).
- **A lookup on every request.** Every verified request first calls the store: 0.001 ms in the application's memory and 0.125–0.178 ms over loopback HTTP from http.client at concurrency 1, 0.312–0.900 ms at concurrency 4 (see [Latency](#latency-2)). The application also verifies the signature again after each lookup; trusting the store, or caching verified tokens, would save the verification but means the store, not the signature, decides what is valid. That alternative was not measured.
- **The store is new state.** The token no longer travels, but it has to be kept: the run stored every token on the server, including the 300,000-byte probe, and the store grows with the number of live references (not measured). The memory store belongs to one application process, so a second application instance, or a restart, would not know its references (not measured); the remote store is shared by whatever reaches it, but it is one more process to run, secure, and keep available, and every reference is lost when it stops.

### Latency

The S3-01 workload ([END_TO_END_RESULTS.md](END_TO_END_RESULTS.md#workload)) ran three times, each on a new stack, in this fixed order: Bearer JWTs (`latency-jwt`), Bearer references with the memory store (`latency-ref-memory`), and Bearer references with the remote store (`latency-ref-remote`). Each was a closed loop of `GET /api/token/verify?timing=1&nonce=<32 hex digits>` requests with OIDC tokens, from http.client threads and from Chromium's test page, at concurrency 1 and 4, with 1 second of warm-up and 2 seconds measured per cell, `--header-buffers 32k`, and `--upstream-keepalive 64`; size-control cells were off. In the reference runs each cell got its reference through nginx from `/api/token/reference?delivery=body`, outside the timed window. The same header carries a JWT and a reference, so the comparison isolates the reference. Every measured request verified: 171,858 with JWTs, 184,586 with the memory store, and 127,742 with the remote store, none failed, and every cell had at least 2,198 verified requests.

Latency is the client-measured time from sending a request to reading its whole response body, in milliseconds; p95 is nearest-rank. Each difference is a reference run's mean minus the JWT run's mean, so a positive difference means the reference was slower. Chromium coarsens its timer to about 0.1 ms, so its medians and p95 values are multiples of 0.1 ms.

**http.client (direct), concurrency 1**

| Configuration | Token | JWT mean | Ref (memory) mean | Ref (remote) mean | Memory difference | Remote difference | JWT median | Memory median | Remote median | JWT p95 | Memory p95 | Remote p95 | JWT req/s | Memory req/s | Remote req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 0.208 | 0.198 | 0.339 | -0.010 | +0.131 | 0.205 | 0.197 | 0.338 | 0.230 | 0.213 | 0.357 | 4,782 | 5,017 | 2,941 |
| ES256 | 948 | 0.223 | 0.213 | 0.351 | -0.010 | +0.128 | 0.221 | 0.213 | 0.350 | 0.242 | 0.225 | 0.365 | 4,465 | 4,665 | 2,841 |
| EdDSA | 948 | 0.223 | 0.213 | 0.349 | -0.010 | +0.127 | 0.220 | 0.212 | 0.349 | 0.244 | 0.224 | 0.363 | 4,473 | 4,682 | 2,853 |
| ML-DSA-44 | 4,095 | 0.243 | 0.205 | 0.345 | -0.039 | +0.101 | 0.236 | 0.204 | 0.344 | 0.272 | 0.216 | 0.358 | 4,089 | 4,861 | 2,891 |
| SLH-DSA-SHA2-128s | 11,353 | 0.418 | 0.335 | 0.500 | -0.083 | +0.082 | 0.415 | 0.334 | 0.501 | 0.441 | 0.344 | 0.510 | 2,387 | 2,977 | 1,994 |
| SLH-DSA-SHA2-128f | 23,662 | 0.697 | 0.529 | 0.697 | -0.168 | +0.001 | 0.695 | 0.528 | 0.698 | 0.713 | 0.542 | 0.709 | 1,433 | 1,888 | 1,431 |

**http.client (direct), concurrency 4**

| Configuration | Token | JWT mean | Ref (memory) mean | Ref (remote) mean | Memory difference | Remote difference | JWT median | Memory median | Remote median | JWT p95 | Memory p95 | Remote p95 | JWT req/s | Memory req/s | Remote req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 0.646 | 0.643 | 0.958 | -0.003 | +0.313 | 0.623 | 0.620 | 0.931 | 0.945 | 0.960 | 1.365 | 6,184 | 6,210 | 4,168 |
| ES256 | 948 | 0.630 | 0.626 | 0.934 | -0.004 | +0.305 | 0.610 | 0.603 | 0.912 | 0.915 | 0.910 | 1.310 | 6,339 | 6,382 | 4,274 |
| EdDSA | 948 | 0.621 | 0.617 | 0.919 | -0.004 | +0.297 | 0.600 | 0.597 | 0.900 | 0.916 | 0.901 | 1.280 | 6,426 | 6,470 | 4,347 |
| ML-DSA-44 | 4,095 | 0.568 | 0.529 | 0.832 | -0.039 | +0.263 | 0.548 | 0.510 | 0.813 | 0.831 | 0.780 | 1.165 | 7,024 | 7,540 | 4,802 |
| SLH-DSA-SHA2-128s | 11,353 | 1.120 | 0.930 | 1.288 | -0.190 | +0.167 | 1.099 | 0.917 | 1.245 | 1.618 | 1.357 | 1.909 | 3,566 | 4,293 | 3,102 |
| SLH-DSA-SHA2-128f | 23,662 | 2.130 | 1.722 | 2.180 | -0.408 | +0.051 | 2.108 | 1.707 | 2.161 | 3.085 | 2.548 | 3.136 | 1,876 | 2,320 | 1,832 |

**Chromium (browser), concurrency 1**

| Configuration | Token | JWT mean | Ref (memory) mean | Ref (remote) mean | Memory difference | Remote difference | JWT median | Memory median | Remote median | JWT p95 | Memory p95 | Remote p95 | JWT req/s | Memory req/s | Remote req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 0.410 | 0.404 | 0.574 | -0.006 | +0.164 | 0.400 | 0.400 | 0.600 | 0.500 | 0.500 | 0.700 | 2,440 | 2,475 | 1,741 |
| ES256 | 948 | 0.477 | 0.439 | 0.588 | -0.038 | +0.111 | 0.500 | 0.400 | 0.600 | 0.600 | 0.500 | 0.700 | 2,094 | 2,276 | 1,698 |
| EdDSA | 948 | 0.460 | 0.433 | 0.582 | -0.027 | +0.122 | 0.400 | 0.400 | 0.600 | 0.500 | 0.500 | 0.700 | 2,173 | 2,307 | 1,717 |
| ML-DSA-44 | 4,095 | 0.484 | 0.421 | 0.570 | -0.063 | +0.087 | 0.500 | 0.400 | 0.600 | 0.600 | 0.500 | 0.700 | 2,065 | 2,372 | 1,752 |
| SLH-DSA-SHA2-128s | 11,353 | 0.625 | 0.523 | 0.692 | -0.102 | +0.067 | 0.600 | 0.500 | 0.700 | 0.700 | 0.600 | 0.800 | 1,599 | 1,912 | 1,444 |
| SLH-DSA-SHA2-128f | 23,662 | 0.910 | 0.704 | 0.909 | -0.206 | -0.000 | 0.900 | 0.700 | 0.900 | 1.000 | 0.800 | 1.000 | 1,099 | 1,420 | 1,099 |

**Chromium (browser), concurrency 4**

| Configuration | Token | JWT mean | Ref (memory) mean | Ref (remote) mean | Memory difference | Remote difference | JWT median | Memory median | Remote median | JWT p95 | Memory p95 | Remote p95 | JWT req/s | Memory req/s | Remote req/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,204 | 0.972 | 0.975 | 1.296 | +0.002 | +0.324 | 0.900 | 0.900 | 1.200 | 1.300 | 1.300 | 1.700 | 4,113 | 4,103 | 3,085 |
| ES256 | 948 | 0.963 | 1.003 | 1.295 | +0.040 | +0.332 | 0.900 | 0.900 | 1.200 | 1.300 | 1.400 | 1.700 | 4,153 | 3,987 | 3,088 |
| EdDSA | 948 | 0.952 | 0.945 | 1.278 | -0.008 | +0.326 | 0.900 | 0.900 | 1.200 | 1.300 | 1.200 | 1.700 | 4,198 | 4,231 | 3,127 |
| ML-DSA-44 | 4,095 | 0.911 | 0.864 | 1.178 | -0.047 | +0.267 | 0.800 | 0.800 | 1.100 | 1.200 | 1.100 | 1.500 | 4,387 | 4,627 | 3,393 |
| SLH-DSA-SHA2-128s | 11,353 | 1.421 | 1.235 | 1.597 | -0.186 | +0.176 | 1.300 | 1.100 | 1.500 | 2.000 | 1.800 | 2.200 | 2,813 | 3,236 | 2,503 |
| SLH-DSA-SHA2-128f | 23,662 | 2.362 | 1.983 | 2.311 | -0.379 | -0.050 | 2.300 | 1.900 | 2.300 | 3.400 | 3.000 | 3.300 | 1,691 | 2,015 | 1,729 |

Where the difference is clearest, http.client at concurrency 1, the components show where it comes from (difference of each component's mean, reference run minus JWT run, in ms; the JWT run's lookup is 0, so the lookup column is the reference run's mean lookup):

| Configuration | Store | Total | Transfer | Other handling | Lookup | Verification |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| RS256 | memory | -0.010 | -0.011 | +0.001 | +0.001 | -0.001 |
| RS256 | remote | +0.131 | +0.001 | +0.002 | +0.127 | +0.001 |
| ES256 | memory | -0.010 | -0.011 | +0.001 | +0.001 | -0.001 |
| ES256 | remote | +0.128 | +0.000 | +0.002 | +0.125 | -0.000 |
| EdDSA | memory | -0.010 | -0.011 | +0.001 | +0.001 | -0.001 |
| EdDSA | remote | +0.127 | +0.000 | +0.002 | +0.125 | -0.000 |
| ML-DSA-44 | memory | -0.039 | -0.038 | +0.001 | +0.001 | -0.002 |
| ML-DSA-44 | remote | +0.101 | -0.026 | +0.002 | +0.128 | -0.002 |
| SLH-DSA-SHA2-128s | memory | -0.083 | -0.085 | +0.002 | +0.001 | -0.000 |
| SLH-DSA-SHA2-128s | remote | +0.082 | -0.075 | +0.001 | +0.164 | -0.007 |
| SLH-DSA-SHA2-128f | memory | -0.168 | -0.171 | +0.004 | +0.001 | -0.002 |
| SLH-DSA-SHA2-128f | remote | +0.001 | -0.163 | +0.001 | +0.178 | -0.015 |

**Noise level.** EdDSA and ES256 tokens are the same size, so the difference between their means shows how much two cells differ without any change in size. With Bearer JWTs it is -0.000 ms from http.client at concurrency 1 and -0.009 ms at concurrency 4, and -0.017 and -0.010 ms from Chromium; with the memory store -0.001, -0.009, -0.006, and -0.058 ms; with the remote store -0.001, -0.016, -0.006, and -0.016 ms. This measures noise within one run only. The three runs ran one after the other, always JWTs first, then the memory store, then the remote store, so a drift between runs affects every configuration's difference alike.

- **The lookup itself.** In the application's memory it took 0.0006 ms on average, which rounds to 0.001 ms in every cell. In the store process it took 0.125–0.128 ms for the classical tokens and ML-DSA-44 and 0.164 and 0.178 ms for the two SLH-DSA tokens from http.client at concurrency 1: one HTTP/1.1 round trip over loopback to another waitress process, which sends the whole token back in its JSON body (4,164 bytes for ML-DSA-44 in `store.log`). At concurrency 4 it took 0.312–0.900 ms, growing with the token, consistent with four application threads queueing at one store process; the queueing itself was not measured.
- **Memory store, http.client:** for the post-quantum configurations the reference was faster, by 0.039, 0.083, and 0.168 ms at concurrency 1 and 0.039, 0.190, and 0.408 ms at concurrency 4, and transfer accounts for all of it at concurrency 1 (0.038, 0.085, and 0.171 ms less), far beyond the noise: the request is 4,048, 11,306, and 23,615 bytes shorter. For the classical configurations the totals moved by -0.010 ms at concurrency 1, with transfer 0.011 ms lower and other handling 0.001 ms higher (the reference parsing and lookup). Their requests are 901–1,157 bytes shorter, and 0.011 ms fits the transfer saving per byte of the post-quantum tokens, but a 0.008 ms transfer drift between two runs was also seen in the cookie-splitting run for a 4-byte change, so these are not attributed to the reference.
- **Remote store, http.client:** every configuration but SLH-DSA-SHA2-128f was slower, by 0.082–0.131 ms at concurrency 1 and 0.167–0.313 ms at concurrency 4. At concurrency 1 the lookup accounts for it: the other components moved by at most 0.015 ms, except transfer for the post-quantum tokens. For SLH-DSA-SHA2-128f the shorter request (0.163 ms less transfer) and the lookup (0.178 ms) cancel, +0.001 ms at concurrency 1 and +0.051 ms at concurrency 4. Throughput fell accordingly: for the classical configurations from 4,465–4,782 to 2,841–2,941 requests per second at concurrency 1.
- **Chromium:** the same pattern within its 0.1 ms timer: the memory store moved the classical configurations by -0.038 to +0.040 ms (within the same-size noise of up to 0.058 ms) and made the post-quantum ones 0.047–0.379 ms faster, and the remote store was 0.067–0.332 ms slower except for SLH-DSA-SHA2-128f (-0.000 and -0.050 ms).

**Modeled network cost (calculated, not measured).** Loopback makes transfer nearly free. From the network model of the JWT run and of the memory-store run (the remote store does not change the request), the modeled upload time of the direct client's request on a new or idle TCP connection (the S3-01 model: bytes at the uplink rate plus one round trip per extra slow-start round, with an initial window of 14,600 bytes) shrinks by, at each illustrative profile:

| Configuration | JWT request bytes | Reference request bytes | Saved bytes | 100 Mbit/s, 10 ms RTT | 10 Mbit/s, 50 ms RTT | 1 Mbit/s, 100 ms RTT |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RS256 | 1,360 | 203 | 1,157 | 0.093 | 0.926 | 9.256 |
| ES256 | 1,104 | 203 | 901 | 0.072 | 0.721 | 7.208 |
| EdDSA | 1,104 | 203 | 901 | 0.072 | 0.721 | 7.208 |
| ML-DSA-44 | 4,251 | 203 | 4,048 | 0.324 | 3.238 | 32.384 |
| SLH-DSA-SHA2-128s | 11,509 | 203 | 11,306 | 0.904 | 9.045 | 90.448 |
| SLH-DSA-SHA2-128f | 23,818 | 203 | 23,615 | 11.889 | 68.892 | 288.920 |

Every reference request is 203 bytes. SLH-DSA-SHA2-128f's 23,818-byte JWT request needs a second slow-start round, which the reference saves, so its saving includes one round trip at every profile. The lookup is not in this model: over a real network the remote store adds its own round trip from the application to the store, which this run measured only over loopback.

### Reproduce

From a clean checkout with the environment from [TRANSPORT.md](TRANSPORT.md#setup), with `TRANSPORT_ENV` set, `TMPDIR` unset (so the stacks' run directories land in `/tmp`), and no other load on the machine:

```bash
make refs
# the same command, which make refs runs with --output-dir results/refs/<UTC time>-<platform>:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py refs --header-buffers 32k --upstream-keepalive 64 --duration 2 --output-dir results/refs/<YYYYMMDDTHHMMSSZ>-macos
# the same settings, from this run's refs.json:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py refs --settings results/refs/20261119T051144Z-macos/refs.json --output-dir results/refs/<YYYYMMDDTHHMMSSZ>-macos
# the JWT latency run alone, from its saved load.json:
"$TRANSPORT_ENV/bin/python" scripts/transport_stack.py load --settings results/refs/20261119T051144Z-macos/latency-jwt/load.json --output-dir /tmp/latency-jwt
```

The run took 4 minutes 12 seconds. `--output-dir` must not exist yet or be empty. [TRANSPORT.md](TRANSPORT.md#the-refs-command) describes every option and output file. The tables above come from `refs.json`, and each latency cell's numbers can be recomputed from its rows in the `raw.csv.gz` files (the reference runs' rows end with `lookup_ns`). The two reference runs' `load.json` files record `"transport": "ref_bearer"` and `ref_store`, which the `load` command does not take, so only the JWT run can be repeated with `load --settings`.

The recorded run's printed output: one line per configuration of the plan (JWT -> reference); per configuration and carrier of the size limits (the measured reference, the derived JWT, and `moved`); each probe; each handling case; and each latency row (the three means, both differences, the two stores' lookups, medians, p95s, and throughput, in the order jwt / ref-memory / ref-remote):

```text
plan     RS256               1,204 -> 47 B  name+value  1,207 -> 54 B  Cookie line  1,218 -> 65 B  Authorization line  1,228 -> 71 B  Set-Cookie  1,279 -> 126 B  jwt fits, ref fits
plan     ES256                 948 -> 47 B  name+value    951 -> 54 B  Cookie line    962 -> 65 B  Authorization line    972 -> 71 B  Set-Cookie  1,023 -> 126 B  jwt fits, ref fits
plan     EdDSA                 948 -> 47 B  name+value    951 -> 54 B  Cookie line    962 -> 65 B  Authorization line    972 -> 71 B  Set-Cookie  1,023 -> 126 B  jwt fits, ref fits
plan     ML-DSA-44           4,095 -> 47 B  name+value  4,098 -> 54 B  Cookie line  4,109 -> 65 B  Authorization line  4,119 -> 71 B  Set-Cookie  4,170 -> 126 B  jwt over per-cookie, ref fits
plan     SLH-DSA-SHA2-128s  11,353 -> 47 B  name+value 11,356 -> 54 B  Cookie line 11,367 -> 65 B  Authorization line 11,377 -> 71 B  Set-Cookie 11,428 -> 126 B  jwt over per-cookie+cookie-line+authorization-line, ref fits
plan     SLH-DSA-SHA2-128f  23,662 -> 47 B  name+value 23,665 -> 54 B  Cookie line 23,676 -> 65 B  Authorization line 23,686 -> 71 B  Set-Cookie 23,737 -> 126 B  jwt over per-cookie+cookie-line+authorization-line, ref fits
limits   cookie RS256               1,204 B  ref 47 B verified                 jwt verified (derived)
limits   bearer RS256               1,204 B  ref 47 B verified                 jwt verified (derived)
limits   cookie ES256                 948 B  ref 47 B verified                 jwt verified (derived)
limits   bearer ES256                 948 B  ref 47 B verified                 jwt verified (derived)
limits   cookie EdDSA                 948 B  ref 47 B verified                 jwt verified (derived)
limits   bearer EdDSA                 948 B  ref 47 B verified                 jwt verified (derived)
limits   cookie ML-DSA-44           4,095 B  ref 47 B verified                 jwt rejected by browser (derived)  moved
limits   bearer ML-DSA-44           4,095 B  ref 47 B verified                 jwt verified (derived)
limits   cookie SLH-DSA-SHA2-128s  11,353 B  ref 47 B verified                 jwt rejected by browser (derived)  moved
limits   bearer SLH-DSA-SHA2-128s  11,353 B  ref 47 B verified                 jwt rejected by proxy (derived)  moved
limits   cookie SLH-DSA-SHA2-128f  23,662 B  ref 47 B verified                 jwt rejected by proxy (derived)  moved
limits   bearer SLH-DSA-SHA2-128f  23,662 B  ref 47 B verified                 jwt rejected by proxy (derived)  moved
probe    SLH-DSA-SHA2-128f  target  65,536 B  pad  31,396   65,536 B  cookie  ref 47 B  verified
probe    SLH-DSA-SHA2-128f  target  65,536 B  pad  31,396   65,536 B  bearer  ref 47 B  verified
probe    SLH-DSA-SHA2-128f  target 300,000 B  pad 207,244  300,000 B  cookie  ref 47 B  verified
probe    SLH-DSA-SHA2-128f  target 300,000 B  pad 207,244  300,000 B  bearer  ref 47 B  verified
handling cookie               store running  status 200  verified      source ref_cookie  ref found        lookup called      verify_token called
handling bearer               store running  status 200  verified      source ref_bearer  ref found        lookup called      verify_token called
handling among_other_cookies  store running  status 200  verified      source ref_cookie  ref found        lookup called      verify_token called
handling unknown              store running  status 401  not verified  source ref_bearer  ref unknown      lookup called      verify_token not called
handling malformed_cookie     store running  status 401  not verified  source ref_cookie  ref malformed    lookup not called  verify_token not called
handling expired              store running  status 401  not verified  source ref_bearer  ref expired      lookup called      verify_token not called
handling revoked              store running  status 401  not verified  source ref_bearer  ref revoked      lookup called      verify_token not called  revoke status 200
handling two_references       store running  status 400  not verified  source -           ref -            lookup not called  verify_token not called
handling reference_and_jwt    store running  status 400  not verified  source -           ref -            lookup not called  verify_token not called
handling reference_as_jwt     store running  status 401  not verified  source cookie      ref -            lookup not called  verify_token not called
handling store_unavailable    store stopped  status 503  not verified  source ref_bearer  ref unavailable  lookup called      verify_token not called
handling jwt_without_store    store stopped  status 200  verified      source bearer      ref -            lookup not called  verify_token called
handling issue_without_store  store stopped  status 503  not verified  source -           ref -            lookup not called  verify_token not called
latency  direct  c=1   RS256               1,204 B  mean jwt 0.208, ref-memory 0.198 (-0.010), ref-remote 0.339 (+0.131) ms  lookup 0.001, 0.127  median 0.205 / 0.197 / 0.338  p95 0.230 / 0.213 / 0.357  4,782.0 / 5,016.8 / 2,940.6 req/s
latency  direct  c=1   ES256                 948 B  mean jwt 0.223, ref-memory 0.213 (-0.010), ref-remote 0.351 (+0.128) ms  lookup 0.001, 0.125  median 0.221 / 0.213 / 0.350  p95 0.242 / 0.225 / 0.365  4,465.2 / 4,665.2 / 2,840.9 req/s
latency  direct  c=1   EdDSA                 948 B  mean jwt 0.223, ref-memory 0.213 (-0.010), ref-remote 0.349 (+0.127) ms  lookup 0.001, 0.125  median 0.220 / 0.212 / 0.349  p95 0.244 / 0.224 / 0.363  4,473.2 / 4,681.5 / 2,853.1 req/s
latency  direct  c=1   ML-DSA-44           4,095 B  mean jwt 0.243, ref-memory 0.205 (-0.039), ref-remote 0.345 (+0.101) ms  lookup 0.001, 0.128  median 0.236 / 0.204 / 0.344  p95 0.272 / 0.216 / 0.358  4,089.5 / 4,861.1 / 2,891.0 req/s
latency  direct  c=1   SLH-DSA-SHA2-128s  11,353 B  mean jwt 0.418, ref-memory 0.335 (-0.083), ref-remote 0.500 (+0.082) ms  lookup 0.001, 0.164  median 0.415 / 0.334 / 0.501  p95 0.441 / 0.344 / 0.510  2,387.5 / 2,976.7 / 1,994.4 req/s
latency  direct  c=1   SLH-DSA-SHA2-128f  23,662 B  mean jwt 0.697, ref-memory 0.529 (-0.168), ref-remote 0.697 (+0.001) ms  lookup 0.001, 0.178  median 0.695 / 0.528 / 0.698  p95 0.713 / 0.542 / 0.709  1,433.4 / 1,887.6 / 1,431.0 req/s
latency  direct  c=4   RS256               1,204 B  mean jwt 0.646, ref-memory 0.643 (-0.003), ref-remote 0.958 (+0.313) ms  lookup 0.001, 0.354  median 0.623 / 0.620 / 0.931  p95 0.945 / 0.960 / 1.365  6,183.6 / 6,210.2 / 4,168.3 req/s
latency  direct  c=4   ES256                 948 B  mean jwt 0.630, ref-memory 0.626 (-0.004), ref-remote 0.934 (+0.305) ms  lookup 0.001, 0.333  median 0.610 / 0.603 / 0.912  p95 0.915 / 0.910 / 1.310  6,339.3 / 6,381.6 / 4,273.9 req/s
latency  direct  c=4   EdDSA                 948 B  mean jwt 0.621, ref-memory 0.617 (-0.004), ref-remote 0.919 (+0.297) ms  lookup 0.001, 0.327  median 0.600 / 0.597 / 0.900  p95 0.916 / 0.901 / 1.280  6,425.8 / 6,469.9 / 4,347.1 req/s
latency  direct  c=4   ML-DSA-44           4,095 B  mean jwt 0.568, ref-memory 0.529 (-0.039), ref-remote 0.832 (+0.263) ms  lookup 0.001, 0.312  median 0.548 / 0.510 / 0.813  p95 0.831 / 0.780 / 1.165  7,023.6 / 7,539.7 / 4,802.3 req/s
latency  direct  c=4   SLH-DSA-SHA2-128s  11,353 B  mean jwt 1.120, ref-memory 0.930 (-0.190), ref-remote 1.288 (+0.167) ms  lookup 0.001, 0.556  median 1.099 / 0.917 / 1.245  p95 1.618 / 1.357 / 1.909  3,566.0 / 4,292.8 / 3,101.9 req/s
latency  direct  c=4   SLH-DSA-SHA2-128f  23,662 B  mean jwt 2.130, ref-memory 1.722 (-0.408), ref-remote 2.180 (+0.051) ms  lookup 0.001, 0.900  median 2.108 / 1.707 / 2.161  p95 3.085 / 2.548 / 3.136  1,876.3 / 2,319.8 / 1,831.8 req/s
latency  browser c=1   RS256               1,204 B  mean jwt 0.410, ref-memory 0.404 (-0.006), ref-remote 0.574 (+0.164) ms  lookup 0.001, 0.144  median 0.400 / 0.400 / 0.600  p95 0.500 / 0.500 / 0.700  2,439.8 / 2,475.3 / 1,741.2 req/s
latency  browser c=1   ES256                 948 B  mean jwt 0.477, ref-memory 0.439 (-0.038), ref-remote 0.588 (+0.111) ms  lookup 0.001, 0.143  median 0.500 / 0.400 / 0.600  p95 0.600 / 0.500 / 0.700  2,093.8 / 2,276.5 / 1,698.5 req/s
latency  browser c=1   EdDSA                 948 B  mean jwt 0.460, ref-memory 0.433 (-0.027), ref-remote 0.582 (+0.122) ms  lookup 0.001, 0.141  median 0.400 / 0.400 / 0.600  p95 0.500 / 0.500 / 0.700  2,172.7 / 2,307.4 / 1,717.3 req/s
latency  browser c=1   ML-DSA-44           4,095 B  mean jwt 0.484, ref-memory 0.421 (-0.063), ref-remote 0.570 (+0.087) ms  lookup 0.001, 0.145  median 0.500 / 0.400 / 0.600  p95 0.600 / 0.500 / 0.700  2,065.1 / 2,372.0 / 1,752.1 req/s
latency  browser c=1   SLH-DSA-SHA2-128s  11,353 B  mean jwt 0.625, ref-memory 0.523 (-0.102), ref-remote 0.692 (+0.067) ms  lookup 0.001, 0.168  median 0.600 / 0.500 / 0.700  p95 0.700 / 0.600 / 0.800  1,599.4 / 1,912.1 / 1,444.1 req/s
latency  browser c=1   SLH-DSA-SHA2-128f  23,662 B  mean jwt 0.910, ref-memory 0.704 (-0.206), ref-remote 0.909 (-0.000) ms  lookup 0.001, 0.182  median 0.900 / 0.700 / 0.900  p95 1.000 / 0.800 / 1.000  1,098.9 / 1,420.1 / 1,098.9 req/s
latency  browser c=4   RS256               1,204 B  mean jwt 0.972, ref-memory 0.975 (+0.002), ref-remote 1.296 (+0.324) ms  lookup 0.001, 0.439  median 0.900 / 0.900 / 1.200  p95 1.300 / 1.300 / 1.700  4,113.4 / 4,102.8 / 3,085.4 req/s
latency  browser c=4   ES256                 948 B  mean jwt 0.963, ref-memory 1.003 (+0.040), ref-remote 1.295 (+0.332) ms  lookup 0.001, 0.420  median 0.900 / 0.900 / 1.200  p95 1.300 / 1.400 / 1.700  4,152.6 / 3,986.5 / 3,087.9 req/s
latency  browser c=4   EdDSA                 948 B  mean jwt 0.952, ref-memory 0.945 (-0.008), ref-remote 1.278 (+0.326) ms  lookup 0.001, 0.411  median 0.900 / 0.900 / 1.200  p95 1.300 / 1.200 / 1.700  4,197.9 / 4,231.4 / 3,126.7 req/s
latency  browser c=4   ML-DSA-44           4,095 B  mean jwt 0.911, ref-memory 0.864 (-0.047), ref-remote 1.178 (+0.267) ms  lookup 0.001, 0.382  median 0.800 / 0.800 / 1.100  p95 1.200 / 1.100 / 1.500  4,387.2 / 4,626.8 / 3,392.8 req/s
latency  browser c=4   SLH-DSA-SHA2-128s  11,353 B  mean jwt 1.421, ref-memory 1.235 (-0.186), ref-remote 1.597 (+0.176) ms  lookup 0.001, 0.605  median 1.300 / 1.100 / 1.500  p95 2.000 / 1.800 / 2.200  2,813.2 / 3,235.9 / 2,502.7 req/s
latency  browser c=4   SLH-DSA-SHA2-128f  23,662 B  mean jwt 2.362, ref-memory 1.983 (-0.379), ref-remote 2.311 (-0.050) ms  lookup 0.001, 0.900  median 2.300 / 1.900 / 2.300  p95 3.400 / 3.000 / 3.300  1,691.4 / 2,014.9 / 1,728.9 req/s
Saved the results to results/refs/20261119T051144Z-macos
```

### Limitations

- **WSL2 was not run.** The `refs` command has not been run on WSL2, so every measurement here is from this Mac. A reference's request and response are small enough for WSL2's 4 KiB `proxy_buffer_size` too, but that is calculated from this run's sizes, not measured.
- **Loopback only.** Every client, nginx, waitress, and the store process ran on one machine over loopback, so the remote store's lookup is a loopback round trip; across a real network it would add at least one network round trip per request. The network cost of the request is only calculated, with S3-01's assumptions (upload only, no loss, no TLS or HTTP/2 framing) and its illustrative profiles.
- **One run each, in a fixed order.** Each of the three latency runs ran once, JWTs first, so run-to-run variation was not measured and a drift between runs cannot be told apart from the classical configurations' small differences. EdDSA's difference from ES256 shows the noise within a run.
- **Derived JWT verdicts.** The JWT column of the size limits is copied from the committed claims run on this Mac ([results/claims/20261118T053507Z-macos/claims.json](claims/20261118T053507Z-macos/claims.json)), recorded at another time with the same documented defaults; it was not measured again here, so this run sent no rejected JWT. With `--claims minimal` no claims run applies, and the verdicts and `moved` are null.
- **The stores are experiment stores.** The memory store is per-process: it lives in one application process and is lost with it; the remote store is a single waitress process over loopback HTTP/1.1 with JSON bodies, not a production store such as Redis, which the team excluded. Both keep expired and revoked entries so they can report `expired` and `revoked` apart from `unknown`; a store with its own time to live, such as Redis's `EXPIRE`, would forget an expired reference and could not tell it from an unknown one. Neither store persists, replicates, or bounds its entries.
- **Re-verification on every request.** The application verifies the JWT's signature after every lookup, so verification stays in every reference measurement. A design that trusts the store or caches verified tokens would save that time (0.049–0.314 ms per request for verification in the JWT run, http.client at concurrency 1); that was not measured.
- **Chromium only, one browser profile.** Firefox and Safari were not measured.
- **HTTP/1.1 without TLS.** The stack serves plain HTTP/1.1 on 127.0.0.1; HTTPS and HTTP/2 (S3-04) would change the request's bytes on the wire and, for the remote store, the cost of its connection.
- **References in one log.** `limits/logs/browser.log.gz` holds the references Chromium received, stored, and sent, as the token check's `browser.log` holds tokens; each names a token only in the memory of a stack that has stopped. No other file holds a reference or a token.
- **Not the default limits.** The three latency stacks raise nginx's header buffers with `--header-buffers 32k`, which SLH-DSA-SHA2-128f's 23,686-byte Bearer line needs, and the non-default `--upstream-keepalive 64`, as recorded in `refs.json` and marked in each `nginx.conf`; the size-limits and behavior stacks keep every default.
- **Machine state.** Nothing else from the project was running, and Spotify, Steam, and Discord were closed. The 1-minute load average was 2.0 when the run started and 5.1 when it ended, including the run's own load.

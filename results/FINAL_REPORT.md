# CIS 643 Final Report: Post-Quantum JWTs in Web Transport

Repository: [github.com/jseara/Post-Quantum-JWT](https://github.com/jseara/Post-Quantum-JWT)

## Overview

This project looks at what happens to JSON Web Token(JWT)-based web logins when tokens are signed with NIST's post-quantum signatures, ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). The same JWT is signed with three classical and three post-quantum algorithms, and each token is sent through a real browser, reverse proxy and application server. Where it breaks, what it costs, and which mitigations fix it are all recorded.

The input is one of three claim sets for one of six signature configurations (RS256, ES256, EdDSA, ML-DSA-44, SLH-DSA-SHA2-128s and -128f), and the run settings: cookie or Bearer header, Chromium or Python's http.client, nginx buffer sizes, protocol, and mitigation. Every request carries a unique request ID that ties it to the log lines proving which layer accepted or rejected it. The outcome is each token's size and signing cost, the largest token each layer accepts and who rejects the next byte, end-to-end latency and throughput, and what each mitigation changes, all saved as JSON with the logs. All testing was run on two systems, Mac OS and WSL2, with runs recorded for each system. 

## Results

**RQ1: How large do JWTs get using NIST algorithms FIPS 204 & FIPS 205?**

With minimal claims, the post-quantum tokens are 16 to 110 times the size of an ES256 token.

| | RS256 | ES256 | EdDSA | ML-DSA-44 | SLH-DSA-SHA2-128s | SLH-DSA-SHA2-128f |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| JWT size (bytes) | 464 | 208 | 208 | 3,355 | 10,613 | 22,922 |
------
**RQ2: How do various layers of a JWT break when the existing limit of 4,096 bytes per cookie is bypassed?**

A token passes five checkpoints, in this order, on its way through the stack. It breaks at the first limit it goes over.

1. **Issue (app → nginx → browser).** A cookie comes back in a `Set-Cookie` header, which nginx has to fit in its response buffer of one memory page: 4 KiB on WSL2, 16 KiB on macOS. Too big, and nginx returns a 502. A Bearer token comes back in the response body, which has no such limit.

   *Breaks here:* Every cookie token over 3,915 bytes on WSL2, and over about 16,200 bytes on macOS, which catches SLH-DSA-SHA2-128f.
2. **Storage (browser).** Chromium silently drops any cookie whose name and value add up to more than 4,096 bytes, so the largest `jwt` cookie token is 4,093 bytes.

   *Breaks here:* SLH-DSA-SHA2-128s's cookie on macOS, and ML-DSA-44's cookie with OIDC claims (4,095 bytes, 2 over).
3. **Request (browser → nginx).** nginx rejects any request header line over 8,192 bytes with a 400, which caps a Bearer token at 8,168 bytes. Over HTTP/2, nginx counts the compressed header instead, so the cap rises to about 10,700–10,900 bytes.

   *Breaks here:* both SLH-DSA tokens as Bearer headers, over HTTP/1.1, HTTPS and HTTP/2 alike.
4. **Forwarding (nginx → waitress).** waitress rejects a header block over 262,144 bytes with a 431.

   *Breaks here:* nothing at the default settings. Only with nginx's header buffers raised to 512k does a token get this far, at about 261,500 bytes.
5. **Verification (application).** Every token that arrives verifies, in under 1 ms.

   *Breaks here:* nothing.
-----
**RQ3: How much slower are FIPS 204 & FIPS 205 due to their larger size?**

Every verification is under 1 ms, though SLH-DSA-SHA2-128s takes 92 ms to sign on macOS. End to end, a request costs 0.029 ms (ML-DSA-44) to 0.496 ms (SLH-DSA-SHA2-128f) more than ES256, and throughput drops from 5,111 to 4,453 and 1,445 requests/s. Size ends up being the larger issue for all post-quantum algorithms.

------
**RQ4: What are some options to mitigate or resolve these issues? This can be either determining overall performance of any given algorithm, or making recommendations for a combination of the two.**

Three alternative designs for getting a large token through were tested:

- **Essential claims** shrink the payload. The token keeps only the five claims a server needs to validate it (`iss`, `sub`, `aud`, `exp` and `iat`) and drops the profile and login details, which saves 641 bytes over the OIDC set. The signature stays the same size.
- **Cookie splitting** spreads one token over several cookies. The app cuts the token into chunks of up to 4,000 bytes, sends each as its own cookie (`jwt.<index>.<count>`), and puts them back together before verifying, so no single cookie goes over Chromium's limit.
- **Reference tokens** keep the JWT on the server. The client only holds a 47-byte random ID in a `jwt_ref` cookie or a Bearer header, and the app looks the JWT up in a store, either in its own memory or in a separate store process, before verifying it.

Two changes to the stack itself were also measured: raising nginx's buffer sizes, and switching protocols to HTTPS or HTTP/2.

Essential claims only fix ML-DSA-44's cookie, while cookie splitting gets past Chromium, but SLH-DSA also needs bigger nginx buffers. A 47-byte reference token passes every limit, at the price of a lookup and of stateless verification. TLS moves no limit, and HTTP/2 only lifts the Bearer limit to about 10,700–10,900 bytes.

ML-DSA-44 in a Bearer header works today, and in a cookie it needs essential claims or splitting. SLH-DSA needs reference tokens, or raised limits on every hop.

## Code written

The project is about 37,500 lines, written almost entirely in Python. Some HTML & Javascript was used to create the test webpage.

## Technical challenges

The first hurdle was that no existing JWT library signs with ML-DSA or SLH-DSA, so a compact JWS encoding was written on top of pqcrypto. The next was knowing which layer rejected a token. Every request was given a unique request ID and traced through the browser, nginx and application logs, and a binary search narrowed each limit down to a single byte.

The two test systems also disagreed on the cookie limit. The difference was traced to nginx's response buffer, which is one memory page in size: 16 KiB on Apple Silicon, but only 4 KiB on WSL2. HTTP/2 brought its own problems. Python's http.client can't speak it, and nginx answers an oversized HTTP/2 header by dropping the connection instead of returning a status code, so Chromium was used as the HTTP/2 client and failures were read from nginx's logs.

Finally, two problems didn't get solved as part of this project. These tests should be run many hundreds of times on cloud VMs to minimize noise & variance per run. Additionally, there are likely costs unaccounted for when running on a real network that do not show up in a small-scale reproduction, even when extra time is factored in. Regardless, the above findings still hold for an initial exploration.

## Reproducing the results and demo

Everything is in the repository linked above, and the [README](../README.md) and [TRANSPORT](TRANSPORT.md) walk through each step. With conda installed, `transport/setup.sh` builds the pinned environment, one `make` target reruns each experiment, and `make test` runs the suite. Size limits reproduce exactly on the same platform; timings vary by machine. For a demo with nothing to install, [jseara.github.io/Post-Quantum-JWT](https://jseara.github.io/Post-Quantum-JWT/) serves the test page read-only: each button replays a recorded result, with the layer that rejected it and its log evidence. `make serve` runs the same page live.

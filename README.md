# CIS628Project: Post-Quantum JWT Benchmarking

This project investigates how post-quantum digital signatures affect JSON Web Tokens (JWTs) and the web infrastructure that carries them. We will compare classical RSA and ECDSA signatures with ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), measuring token size, cryptographic performance, and practical transport limits.

The final deliverable is a reproducible authentication test environment and experimental results covering token size, signing and verification time, throughput, request latency, and possible mitigations for oversized tokens.

## Project status

Planning stage. This repository currently contains the project context in [AGENTS.md](AGENTS.md) and this implementation backlog. No application, benchmark runner, or experimental results have been implemented yet. Setup and run commands will be added as the implementation lands.

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

## Sprint 1: Establish reproducible algorithm benchmarks

**Sprint goal:** From a clean checkout, generate keys, create and verify signed tokens with both classical baselines and one parameter set from each post-quantum family, and export an initial size and timing comparison.

Build the classical baseline first so the shared fixtures, token format, and measurement harness can be checked before adding post-quantum adapters. Browser and proxy testing follows in Sprint 2.

### S1-01 — Choose and document the implementation stack

- [ ] Select the language/runtime, classical JWT library, and post-quantum cryptographic backend after checking support for the initial configurations above.
- [ ] Check JOSE algorithm identifiers, encoding requirements, and whether custom adapters are necessary.
- [ ] Add dependency/version management and clean-checkout setup instructions, including any native build requirements.

**Done when:** A documented setup works in the supported environment, and a small capability check confirms key generation, signing, and verification for all four configurations. Record any interoperability limitations.

### S1-02 — Define shared fixtures and the algorithm interface

- [ ] Add one fixed JWT claim fixture and deterministic JSON serialization for comparable input bytes. Keep time-dependent claim validation separate from static cryptographic measurements.
- [ ] Define a common interface for key generation, signing, and verification, with algorithm and parameter-set metadata.
- [ ] Specify the benchmark output format, including payload bytes, signature bytes, token bytes, operation, duration, iteration, and run/environment metadata.

**Done when:** Every adapter can consume the same signing input and report results through the same schema. Fixtures and keys used for experiments are clearly distinguished from production credentials.

### S1-03 — Implement the classical JWT baselines

- [ ] Implement RS256 with a 2,048-bit RSA key and ES256 with P-256 using established libraries.
- [ ] Generate complete compact signed JWTs and verify them, respecting JOSE signature encoding requirements.
- [ ] Add correctness checks for a valid token, a changed payload, a changed signature, a wrong verification key, and a disallowed algorithm.

**Done when:** Both baselines pass the correctness checks and produce measured signature and complete token sizes for the shared fixture.

### S1-04 — Integrate ML-DSA and SLH-DSA

- [ ] Add ML-DSA-44 and SLH-DSA-SHA2-128s adapters using the selected backend.
- [ ] Integrate their signatures into the compact token flow with documented algorithm identifiers and encoding rules.
- [ ] Run the same positive and negative correctness checks as the classical adapters, and check signature lengths against the relevant standards.

**Done when:** Both post-quantum configurations create and verify tokens over the shared fixture. Documentation identifies backend versions and any experimental JWT integration. A backend or JOSE blocker must be recorded explicitly rather than substituting an older algorithm silently.

### S1-05 — Build the local benchmark runner

- [ ] Add a repeatable command that runs all four configurations with configurable warm-up and measured iterations.
- [ ] Measure signing and verification independently with keys and fixtures prepared outside the timed loops; report signature and complete token sizes.
- [ ] Export raw timings and run metadata to CSV or JSON, plus median and p95 summaries. Exclude setup, file output, and summary generation from operation timings.

**Done when:** A run produces inspectable raw data and a summary for all four configurations, and its settings can be reused for another run. Do not use timing thresholds as correctness tests.

### S1-06 — Publish the first comparison and reproduction steps

- [ ] Run the benchmark in a recorded environment and check that all generated tokens verify.
- [ ] Add a small results table comparing signature bytes, JWT bytes, signing latency, and verification latency, with links to the raw data and run settings.
- [ ] Document the exact setup and execution commands, measurement limitations, and follow-up questions for transport testing.

**Done when:** Another team member can reproduce the workflow from a clean checkout, and reported results can be traced to a specific configuration and dataset.

**Sprint 1 completion:** All six tasks are complete, all four algorithm configurations pass correctness checks, and the repository contains a runnable benchmark, raw measurements, and an initial comparison. Do not fill result tables with estimates presented as measurements.

## Follow-up backlog

- **Sprint 2 — Transport limits:** Build the browser/proxy/application path; exercise cookie and bearer-header transport; sweep token sizes around observed limits; capture rejection evidence and configuration at each layer.
- **End-to-end performance:** Measure request latency and throughput under a defined workload, distinguishing cryptographic costs from token transfer and server handling.
- **Mitigations:** Compare smaller claim sets, cookie splitting/reassembly, and reference tokens using the same workload. Account for cookie count/aggregate header limits, failure handling, and reference-token lookup costs.
- **Expanded comparisons:** Add further parameter sets and repeat runs to assess variability and the tradeoffs among signature size, speed, and security strength.

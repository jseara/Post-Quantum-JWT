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
- [ ] Specify the benchmark output format, including payload bytes, signature bytes, token bytes, operation, duration, iteration, and run/environment metadata.

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
This file is meant to serve as a way to give context to any agentic workflow.

Here is project proposal:

ntroduction
Our current digital signature algorithms (RSA, ECDSA), have been proven to no longer be secure against attack by quantum computers. NIST (National Institute of Standards and Technology) is in the middle of trying to review a series of cryptographic algorithms that may resolve these issues. Issues arise when discussing real-world implementation of these algorithms. Much existing infrastructure, including JSON Web Tokens (JWTs), are not capable of handling the increased size and complexity of these algorithms. None of the algorithms have been implemented at scale, but since many of their details have been published in RFCs, testing can be done at this time.

A significant amount of testing has been done on how these algos interact with TLS (Transport Layer Security), the actual protocol currently in use. This is due to the fact that a malicious actor can store secure communications using TLS until quantum computing becomes available and decrypt said communications at that time. Implementation of these post-quantum algorithms into our existing TLS protocol can help future proof current communications, and so it is the focus of much current research.

To attempt to look at the problem from a different angle, we will be reviewing how two of these post-quantum algorithms interact with and break our current JWT-based web infrastructure. The algorithms chosen were FIPS 204 & FIPS 205, as they have had full or draft RFCs published and therefore we can create templates for them. Our primary research questions are listed below.

RQ1. How large do JWTs get using NIST algorithms FIPS 204 & FIPS 205? 
RQ2. How do various layers of a JWT break when the existing limit of 4,096 bytes per cookie is bypassed?
RQ3. How much slower are FIPS 204 & FIPS 205 due to their larger size?
RQ4. What are some options to mitigate or resolve these issues? This can be either determining overall performance of any given algorithm, or making recommendations for a combination of the two.
Literature Review

Paper 1 - Post-Quantum Authentication in TLS 1.3: A Performance Study
	
	This paper does similar explorations of post-quantum authentication schema and how they interact with modern TLS-based protocols. It argues that understanding how these schema interact with modern protocols is key to implementation and that it needs to be resolved sooner rather than later to avoid retroactive decryption of modern communications. The methodology used here is a good base for us to base our work off of, as well as compare their final results to see if one schema shows particular promise.

Paper 2 - The SPHINCS+ Signature Framework

	A detailed explanation of the SPHINCS+ framework written by the original creators, Bernstein, Hülsing, et al. SPHINCS+ is a hash-based signature scheme, building off of a foundation nearly 50 years old. SPHINCS+ solves a number of historic issues with hash-based signatures. It goes into depth on the new features that set it apart, including its statelessness, ability to tweak existing hash-functions, and performance improvements across the board.

	It additionally has a discussion on the security of the scheme, providing proofs on how well it can stand up to both classical and post-quantum attacks against DM-SPR, PRF Security, and ITSR. 

Paper 1 - Exploring Lattice-based Post-Quantum Signature for JWT Authentication: Review and Case Study

Prior work has demonstrated that post-quantum signatures can be used with JWT authentication. Alkhulaifi and El-Alfy compared Dilithium and qTESLA with RSA and found that lattice-based signatures could provide competitive performance, although their signatures and keys were substantially larger than RSA equivalents.[3]

Paper 2 - Secure Enhanced JWT Framework with Post-Quantum Cryptography

More recently, Sunera et al. implemented an ML-DSA-based JWT framework and evaluated latency, throughput, token size, validation, key distribution, and revocation.[4] Our project builds on this work by focusing specifically on how larger post-quantum JWTs interact with existing web infrastructure and practical token-size limitations.

Methodology
We will implement a small JWT authentication test environment and compare traditional signature algorithms, such as RS256 and ES256, with NIST post-quantum signature algorithms ML-DSA and SLH-DSA. Identical JWT payloads will be signed with each algorithm so that token size, signing and verification time, throughput, and end-to-end request latency can be compared. We will then send the tokens through a browser-to-web-server-to-application environment using both cookies and Authorization: Bearer headers. Token sizes will be increased to determine where practical limits are encountered and which layer rejects the request. Finally, we will test possible mitigations such as reducing JWT claims, splitting tokens, or replacing large JWTs with smaller reference tokens.

Rather than evaluating only the cryptographic performance of post-quantum signatures, this project focuses on their effect on existing JWT-based web infrastructure. The final deliverable will be a working test environment and experimental results comparing token size, performance, transport limitations, and mitigation techniques for classical and post-quantum JWTs.
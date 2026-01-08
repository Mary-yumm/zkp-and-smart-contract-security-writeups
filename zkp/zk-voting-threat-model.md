# What Does My ZK Voting System Actually Prove?

*A security and threat-modeling perspective on a ZK-enabled blockchain voting system*
*Source code:* https://github.com/Mary-yumm/Zero-Knowledge-Proof-Voting-DApp

---

## 1. Motivation

Electronic voting systems sit at the intersection of two goals that are often in tension:

- **Privacy**: individual votes must remain secret  
- **Verifiability**: the public must be able to check that the final result is correct  

Most systems end up prioritizing one over the other. Public blockchains are a common example. They make state changes easy to verify, but actions are directly tied to identities, usually wallet addresses.

Zero-Knowledge Proofs (ZKPs) seem like a natural way to bridge this gap. They allow something to be verified without revealing the underlying data. In practice, this only works if the system is designed very carefully.

I built this system to understand how ZKPs behave in a full application, not just inside isolated circuits. Early on, I assumed that adding ZK proofs would automatically give me privacy and security. That assumption did not hold up once I started integrating everything end to end.

This post is not a guide on how to build a ZK voting DApp. It is an attempt to be precise about what this system actually proves, what assumptions it relies on, and where it can break.

The system is implemented using Circom, Groth16, and Ethereum smart contracts. Proofs are generated client-side in the browser.

---

## 2. System Overview (High Level)

At a high level, the system separates voter eligibility from voter identity.

Voters are registered off-chain using cryptographic commitments. Eligibility is later proven inside a ZK circuit using a Merkle membership proof. Votes are cast by submitting a valid proof to an Ethereum smart contract.

The blockchain never learns who voted. It only checks that an eligible vote was submitted.

This separation looks simple on paper. In practice, I found that even small mistakes in how signals are classified as public or private can leak more information than intended.

### System Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (React)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
│  │ Connect     │  │ Admin Panel │  │ Voter Panel │                  │
│  │ Wallet      │  │ (Add Cands) │  │ (Cast Vote) │                  │
│  └─────────────┘  └─────────────┘  └──────┬──────┘                  │
│                                           │                         │
│                              ┌────────────▼────────────┐            │
│                              │  ZK Proof Generation    │            │
│                              │  (snarkjs in browser)   │            │
│                              └────────────┬────────────┘            │
└───────────────────────────────────────────┼─────────────────────────┘
                                            │
                    ┌───────────────────────▼───────────────────────┐
                    │              BLOCKCHAIN (Ethereum)            │
                    │  ┌─────────────────┐  ┌─────────────────┐     │
                    │  │   VotingZK.sol  │  │  Verifier.sol   │     │
                    │  │  (Main Logic)   │◄─┤  (Proof Check)  │     │
                    │  └─────────────────┘  └─────────────────┘     │
                    └───────────────────────────────────────────────┘

```
---

## 3. Threat Model

Before talking about guarantees, the threat model needs to be explicit. Without it, security claims are vague and easy to misinterpret.

### Adversary Capabilities

The adversary may:

- Observe all on-chain data  
- Interact with the smart contracts arbitrarily  
- Attempt to submit malformed or forged proofs  
- Attempt to vote multiple times  
- Control the frontend environment of their own browser  

The adversary is **not** assumed to:

- Break standard cryptographic assumptions such as hash preimage resistance 
- Compromise the proving system itself  

Being clear about these limits helped me reason about what the system can realistically promise.
---

## 4. What the ZK Circuit Proves

The core of the system is a Circom circuit that enforces the following statements:

### 4.1 Membership Proof

> *"I know a secret whose Poseidon hash exists as a leaf in the registered voter Merkle tree."*

This ensures that **only registered voters** can generate a valid proof, without revealing which voter they are.

While implementing this, I underestimated how fragile this logic can be. Small errors in tree construction or index handling can silently weaken the guarantee.
---

### 4.2 Vote Validity

The circuit checks that the selected `candidateId` falls within a valid range.

This constraint is simple, but it matters. Without it, the system would still accept proofs while recording votes that do not correspond to any real candidate.
---

### 4.3 Nullifier Construction

A deterministic nullifier is computed as:

```text
nullifier = Poseidon(secret, 1)
```


This value is made public and used by the smart contract to prevent double voting.
The circuit proves:

> "This vote corresponds to a unique secret that has not been used before."

While designing the nullifier, it became clear how easy it is to introduce unintended linkability if extra public inputs are added without careful thought.
---

## 5. What the Smart Contract Verifies

On-chain, the `VotingZK` contract performs three critical checks:

- It verifies the proof using the Groth16 verifier contract 
- It rejects proofs with a nullifier that has already been used
- It records the vote for the chosen candidate  

The contract never stores voter addresses, secrets, or Merkle paths. Only public proof outputs are visible on-chain.

While integrating the verifier, I ran into an important lesson. A correct circuit is not enough. If the verification key or public inputs are wired incorrectly, the system can become insecure without failing loudly.

---

## 6. Security Guarantees (What the System Actually Ensures)

Under the assumptions described so far, the system provides the following guarantees:

- **Eligibility:** only someone who knows a valid voter secret can vote

- **Anonymity:** on-chain data does not link votes to voter identities or wallets

- **Double-voting prevention:** each secret can only be used once

- **Public verifiability:** anyone can verify that all recorded votes correspond to valid proofs and that the final tally is correct

All of these guarantees depend on the defined threat model.

---

## 7. Trust Assumptions (Critical)

Several important assumptions sit outside the ZK circuit itself.

Groth16 requires a trusted setup. The system assumes that at least one participant in the Powers of Tau ceremony behaved honestly.

Voter secrets must be distributed securely. If a secret leaks, the system cannot tell whether a vote came from the original voter or someone else.

The circuit must be correct. ZK proofs only enforce what the circuit specifies. Bugs in the logic directly weaken the security properties.

The smart contract must also verify proofs against the correct verification key. Any mismatch breaks the intended guarantees.

Understanding how much trust sits outside the proof system was one of the more sobering parts of building this project.

---

## 8. What This System Does NOT Protect Against

It is equally important to state what this system does not solve:

- Coercion resistance  
- Vote buying  
- Frontend compromise  
- Key compromise  

Being explicit about these limits matters. ZK proofs do not automatically solve social or endpoint-level problems.

---

## 9. Lessons Learned

The main lesson from this project is straightforward.

ZK proofs do not add security on their own. They enforce exactly the statements you encode, and nothing else.

The hardest part of the project was not writing constraints. It was reasoning about which signals are public, where trust is assumed, and how failures can appear outside the proof system entirely.

---

## 10. Conclusion

This project shows that ZK proofs can support anonymous and verifiable voting, but only within a clearly defined threat model.

What mattered most was not the cryptography itself, but understanding what the system actually proves in practice. Treating ZK-based systems as security-critical infrastructure, rather than as black-box tools, changed how I approach their design. That is the perspective I want to keep developing as I continue working in applied cryptography and security.

---

**Author:** Maryam Masood

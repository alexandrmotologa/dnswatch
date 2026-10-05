# DNSSEC Validation Guide

DNS Security Extensions (DNSSEC) protect applications from DNS spoofing and cache poisoning by adding cryptographic signatures to DNS records.

## Chain of Trust Concepts

1. **Root Zone (`.`):** The Internet root zone has a trust anchor published by IANA. Root DNSKEY records sign the root zone, including Delegation Signer (DS) records for top-level domains.
2. **TLD Zone (e.g., `.com`, `.org`):** TLD zones contain DS records corresponding to child second-level domains. The parent DS record contains a cryptographic digest of the child Key Signing Key (KSK).
3. **Child Zone (e.g., `example.com`):** The authoritative nameservers publish:
   - DNSKEY: Contains Key Signing Keys (KSK, flags 257) and Zone Signing Keys (ZSK, flags 256).
   - RRSIG: Digital signature created with a private key covering a specific RRset.
   - NSEC / NSEC3: Authenticated denial of existence records.

## Validation Steps in DNSWatch

When evaluating a domain name:
1. Fetch DNSKEY records for the domain and extract KSK and ZSK public keys.
2. Query parent zone for DS records of the domain.
3. Verify that at least one DS record digest matches the computed digest of a KSK DNSKEY record.
4. Verify the RRSIG over the DNSKEY RRset using the verified KSK.
5. Verify the RRSIG over the requested RRset (e.g., A, MX) using the validated ZSK.
6. Verify time validity: `inception <= current_time <= expiration`.

## Supported Algorithms and Digests

### Digest Types (DS Records)
- Type 1: SHA-1 (flagged as legacy/weak)
- Type 2: SHA-256 (standard)
- Type 4: SHA-384 (recommended for high security)

### Key Algorithms
- Algorithm 5: RSA/SHA-1 (deprecated, flagged with warning)
- Algorithm 7: RSASHA1-NSEC3-SHA1 (deprecated, flagged with warning)
- Algorithm 8: RSA/SHA-256
- Algorithm 10: RSA/SHA-512
- Algorithm 13: ECDSA Curve P-256 with SHA-256 (recommended)
- Algorithm 14: ECDSA Curve P-384 with SHA-384
- Algorithm 15: Ed25519 (modern, fast)
- Algorithm 16: Ed448

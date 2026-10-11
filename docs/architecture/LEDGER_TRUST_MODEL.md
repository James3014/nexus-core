# Ledger Trust Model

## Ledger signatures are unauthenticated metadata

`product.ledger` is a carrying layer. Its integrity guarantee is a hash chain, not
signer authentication (issue #163).

### What is guaranteed

- Chain integrity: `verify_chain` detects corruption, truncation, sequence gaps,
  non-monotonic generations, broken `previous_entry_hash` links, and tampering with any
  field covered by the entry hash.
- The entry hash (`compute_entry_hash`) covers: `schema`, `ledger_id`, `sequence`,
  `committed_generation`, `request_id`, `idempotency_key`, `request_hash`,
  `envelope_hash`, `receipt_hash`, `factual_disposition`, `claim_ceiling`,
  `source_snapshot_hash`, `previous_entry_hash` and `signer_public_metadata`.
  Envelope and receipt bytes are re-hashed against their stored hashes.
- Receipt semantics are validated on append (disposition, claim ceiling, receipt hash).

### What is not guaranteed

- Signer authenticity. `signature`, `signer_algorithm`, `signer_key_id`, `created_at`,
  `attempt` and `expected_generation` are not covered by the entry hash. They can be
  altered without changing the entry hash, and `verify_chain` will still report VALID.
- `signer_public_metadata` is free-form. It is hash-covered, so changes are detected,
  but its content is supplied by the signer port and is never authenticated.
- `ExternalSignerPort` only signs. Nothing in the ledger verifies a signature.

Consumers that need signer authentication must verify signatures out of band, with their
own key material, over the digest they trust. A VALID `verify_chain` result must not be
read as "signed by key X".

### Rejected alternatives (possible future work)

The owner chose to document the assumption with no behaviour change. Two options were
considered and rejected for now:

- (a) An optional `ExternalSignatureVerifierPort` that `verify_chain` would call to
  verify stored signatures against caller-supplied key material.
- (b) A versioned v2 entry hash that also covers the signature fields (signature, key id,
  algorithm). This changes persisted hashes and needs a migration and schema bump.

The behaviour described here is pinned by
`test_signature_and_key_id_are_unauthenticated_metadata` in `tests/product/test_ledger.py`.

# Lab report digests

The strict lab-report validator (`it_grc.lab_report.import_lab`) gives every report two
identities. `it-grc push` prints the record digest before it contacts CISO Assistant,
and the ledger records both digests with every push.

- `artifact_sha256` hashes exactly the bytes of the report file. `artifact_digest_kind`
  is `raw_file_bytes`.
- `record_sha256` hashes the parsed report serialized as
  `json-sort-keys-compact-ascii-v1`: sorted object keys, compact comma and colon
  separators, ASCII escapes, UTF-8 encoding, and no non-finite numbers.

The record format is a project contract, not RFC 8785. It ignores whitespace and object
key order; array order, numeric representation and unknown report fields remain
significant. Two files with the same parsed report have the same record digest and
different artifact digests when their bytes differ.

Each evidence revision the bridge uploads is a deterministic JSON extract of one scenario
group. It carries both report digests, the capture time, the backend and the producer
revisions, so a stored attachment can be traced back to the report it came from. The
same report always yields the same extract bytes; see [Mapping and push](mapping.md).

A digest detects byte changes relative to a trusted comparison value. It is not an
authenticated signature, a provenance proof or evidence of the current cluster state.
Body size checks and the safe-field projection remain separate controls.

# Independent provenance

This repository starts from newly written specifications and its own materials. No previous implementation, private reference material or external company artifact is an input to this project.

Permitted inputs are public standards and official guidance, the public upstream CISO Assistant Community edition used over its REST API, and explicitly selected reports from independent personal projects. Record the source and applicable license when adding external material.

Do not import old source, prompts, document templates, internal terminology, control catalogs, screenshots or UI layouts. Familiarity with a general security workflow does not make private artifacts reusable.

The public upstream CISO Assistant Community edition is used unmodified as an external service over its REST API. Its public framework libraries are loaded into that service by URN. No upstream source code, serializers, API schemas or library YAML are copied into this repository. See [ADR 0001](adr/0001-ciso-assistant-system-of-record.md).

The mapping in `mappings/hipaa-800-66r2.json` is this project's own reading of the public NIST SP 800-66 rev2 framework. It refers to requirement nodes by URN and records the node name and section observed through the API on 2026-10-13; it does not copy the library. Public HHS references are listed in `references/sources.json` with their access date. The catalog records checked URLs, not a frozen copy of regulations. Proposed regulatory changes are not treated as effective requirements.

The lab report fixture `fixtures/lab/demo-report-2026-10-13.json` is an executed report from the independent `mcp-svid-auth` security lab on synthetic data. It holds scenario numbers, outcomes and lab parameters only: no patient data, hosts or credentials. Any new executed lab evidence must carry its own origin, capture time and revision.

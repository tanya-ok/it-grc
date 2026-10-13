<p class="project-kicker">Security lab evidence / GRC system of record</p>

# Put executed lab evidence where reviewers look.

<p class="project-lead">IT GRC pushes executed security-lab scenarios into CISO Assistant Community edition as evidence revisions and capped requirement results, then verifies them against a local hash-chained ledger.</p>

## How it works

```mermaid
---
config:
  theme: base
  themeVariables:
    primaryTextColor: '#183452'
    textColor: '#183452'
    lineColor: '#7b8797'
    edgeLabelBackground: '#e8effa'
    fontFamily: 'Arial, sans-serif'
    fontSize: '15px'
  flowchart:
    nodeSpacing: 24
    rankSpacing: 28
    padding: 12
---
flowchart LR
    accTitle: Lab report to the it-grc bridge to CISO Assistant in the it-grc VM
    accDescr: A security-lab report with 18 executed scenarios is validated and mapped by the it-grc bridge on the host. The bridge pushes evidence and capped results over HTTPS to the unmodified CISO Assistant CE in the it-grc Lima VM and records every push in a local ledger. A human reviewer makes the compliant and done decisions in CISO Assistant.
    R["Security-lab report<br/>18 executed scenarios"] --> B["it-grc bridge<br/>validate, map, push, verify"]
    B --> C["CISO Assistant CE<br/>REST API, it-grc Lima VM"]
    B --> L[("Local ledger<br/>hash chain")]
    H["Human reviewer"] -.-> C
    classDef source fill:#e8effa,stroke:#5276a2,color:#183452,stroke-width:1.5px
    classDef core fill:#e0f3ec,stroke:#328267,color:#173f33,stroke-width:1.5px
    classDef limit fill:#fff0dc,stroke:#b27b36,color:#63421d,stroke-width:1.5px
    class R source
    class B,C,L core
    class H limit
```

- The lab report passes a strict validator, then a versioned mapping turns 18 scenarios into partial evidence for 20 NIST SP 800-66 rev2 requirement nodes and lists 97 requirements as `not_verified`.
- The bridge creates or updates the audit, 9 evidence objects with hashed revisions, one applied control and the mapped requirement assessments, capped at `partially_compliant` and `in_review`.
- Every push lands in a local ledger. `it-grc verify` compares CISO Assistant with it and reports drift; human decisions are listed as `HELD`.

![CISO Assistant audit overview of the IT GRC lab audit with the Compliance, Extended result and Progress donuts](assets/ciso-audit-overview.webp)

[Run the demo](demo.md){ .overview-link }
[Read the article](article.md){ .overview-link }
[Deployment](deployment.md){ .overview-link }
[Mapping and push](mapping.md){ .overview-link }
[ADR 0001](adr/0001-ciso-assistant-system-of-record.md){ .overview-link }

!!! note "Scope"
    Executed lab scenarios on synthetic data. Lab evidence is not HIPAA compliance, and NIST SP 800-66 rev2 is guidance, not the rule. `compliant`, `done` and evidence approval stay human decisions in CISO Assistant. IT GRC is Apache-2.0; CISO Assistant CE is AGPL-3.0-or-later and runs unmodified as an external service.

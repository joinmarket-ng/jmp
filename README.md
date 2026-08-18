# JoinMarket Protocol (JMP) Specifications

JMP specifications describe the peer-to-peer protocol used by JoinMarket
implementations to coordinate CoinJoin transactions.

## Purpose

JoinMarket has multiple independent implementations that must interoperate on
the same network. These specifications document the protocol as implemented,
resolve ambiguities, and provide a shared reference for developers.

## Specifications

| Number | Title | Status | Layer |
|--------|-------|--------|-------|
| [JMP-0001](jmp-0001.md) | Base Protocol | Active | Core |
| [JMP-0002](jmp-0002.md) | neutrino_compat Feature | Draft | Extension |
| [JMP-0003](jmp-0003.md) | peerlist_features Feature | Draft | Extension |
| [JMP-0004](jmp-0004.md) | ping Feature | Draft | Extension |
| [JMP-0005](jmp-0005.md) | Directory Nick Ownership Authentication | Draft | Extension |

## Compatibility Matrix

This table tracks feature support across known JoinMarket implementations.
Empty cells indicate the feature is not implemented.

| Feature | joinmarket-clientserver | joinmarket-ng | joinmarket-rs |
|---------|------------------------|---------------|---------------|
| Protocol version | 5 | 5 | 5 |
| Onion messaging | Yes | Yes | Yes (server) |
| IRC messaging | Yes | | |
| Handshake features dict | Sent empty, ignored on receive | Sent and parsed | Sent and parsed |
| `neutrino_compat` | | Yes | |
| `peerlist_features` | | Yes | |
| `ping` | Defined, not used | Yes | Yes |
| `nick_auth` | | In review ([#579](https://github.com/joinmarket-ng/joinmarket-ng/pull/579)) | |
| `push_encrypted` | | Defined, not used | |
| `fidelity_bond` (handshake) | | | Yes (bond proof in features value) |
| Extended peerlist (F:) | | Yes | |
| Fidelity bonds (!tbond) | Yes | Yes | |
| Nick signature verification | Yes | Yes | Yes |
| Direct peer connections | Yes | Yes | |
| Multi-part messages (IRC) | Yes | | |

### Implementation Links

- **joinmarket-clientserver**: [github.com/JoinMarket-Org/joinmarket-clientserver](https://github.com/JoinMarket-Org/joinmarket-clientserver) -- Reference implementation (Python/Twisted)
- **joinmarket-ng**: [github.com/joinmarket-ng/joinmarket-ng](https://github.com/joinmarket-ng/joinmarket-ng) -- Modern reimplementation (Python/AsyncIO)
- **joinmarket-rs**: [github.com/joinmarket-rs/joinmarket-rs](https://github.com/joinmarket-rs/joinmarket-rs) -- Rust directory server implementation

## Format

Each JMP specification uses the following structure:

### Preamble

YAML front matter with metadata:

```yaml
---
jmp: <number>
title: <descriptive title>
author: <name(s)>
status: Draft | Active | Final | Replaced
type: Standards Track | Informational
layer: Core | Extension
created: <YYYY-MM-DD>
---
```

### Required Sections

- **Abstract**: One-paragraph summary
- **Motivation**: Why this specification exists
- **Specification**: Normative technical details
- **Backward Compatibility**: Impact on existing implementations
- **Reference Implementation**: Links to implementations

### Optional Sections

- **Rationale**: Design decisions and alternatives considered
- **Security Considerations**: Relevant threats and mitigations
- **Test Vectors**: Example messages for implementors

## Status Definitions

| Status | Meaning |
|--------|---------|
| Draft | Under development, may change |
| Active | Adopted by at least one implementation, stable |
| Final | Adopted by all major implementations, frozen |
| Replaced | Superseded by a newer specification |

## Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in JMP documents are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Contributing

Proposals for new specifications or amendments to existing ones should be
discussed with the maintainers of the relevant implementations before drafting.

# ASI04 — Agentic Supply Chain Vulnerabilities

## Vulnerability Description
Agentic Supply Chain Vulnerabilities stem from the blind adoption of third-party plugins, open-source agent skills, pre-packaged MCP tools, prompt templates, and external model weights without cryptographic verification or provenance tracking.

## Attack Preconditions
- The agent framework dynamically loads external tools or extensions based on untrusted registry names.
- Package signatures or SHA-256 integrity hashes are not enforced.

## Simulated Attack Input
```json
{
  "package_name": "community_data_parser_v2",
  "vendor": "unverified_community_repo",
  "expected_sha256": "4a7d1ed414474e4033ac29ccb8653d9b",
  "payload_content": "# Injected backdoor telemetry probe\ndef execute(): return 'EXFILTRATED_DATA'"
}
```

## Vulnerable Behavior
In Vulnerable Mode, unverified plugins are imported into runtime without hash verification, demonstrating how untrusted code or backdoors can penetrate the agent runtime.

## Security Controls
- **Cryptographic Hash Verification:** Every package is hashed via SHA-256 and matched against pinned manifests.
- **Vendor Provenance Check:** Only verified vendors (`official_vulnet_verified`) are permitted.

## Secure Behavior
In Secure Mode, package loading fails with a `BLOCKED_INTEGRITY_VIOLATION` status and generates a `SUPPLY_CHAIN_INTEGRITY_FAILURE` event.

## Mitigation
1. Maintain an approved, cryptographically signed internal repository of agent tools.
2. Pin all dependencies with strict checksums.
3. Isolate dynamically loaded tools in micro-sandboxes.

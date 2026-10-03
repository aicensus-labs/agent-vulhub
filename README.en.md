# Agent Vulhub

[简体中文](README.md)

A collection of reproducible vulnerability environments for Agent and MCP software. Each environment pins an affected version and a patched version, and includes Docker configuration, reproduction scripts, a verifier, and test inputs for checking the trigger path and patched behavior in isolation.

> [!WARNING]
> This project is independent of the official Vulhub project. PoCs are provided for authorized testing and security research only. Run them in a disposable environment; do not use production credentials or connect to production services. All environments are currently `draft`, and reproduction results are not a complete security assessment.

## Project Status

As of the current repository snapshot:

| Item | Count |
| --- | ---: |
| Environments | 276 |
| Mechanism checks passed | 275 |
| Not run | 1 |

## Environment Contents

Environments are organized by product and vulnerability identifier:

```text
environments/<product>/<CVE-or-GHSA>/
├── metadata.toml       # Versions, sources, and verification status
├── Dockerfile          # Vulnerable and patched image build recipe
├── compose.yaml        # Local runtime configuration
├── reproduce.py        # Reproduction entry point
├── verify.py           # Independent verifier
└── fixtures/           # Fixed inputs and test materials
```

Source revisions, base images, and build dependencies are recorded in `metadata.toml`. Builds use pinned inputs locally and do not require prebuilt images. The first build needs network access; later runs can use `--offline` with the local cache.

## Quick Start

Static checks require Python 3.11+. Full reproduction requires Linux amd64, Docker Engine, and the Compose plugin.

```sh
git clone https://github.com/aicensus-labs/agent-vulhub.git
cd agent-vulhub

python3 -m runner list
python3 -m runner check
python3 -m runner lint
```

Run an environment:

```sh
python3 -m runner reproduce mcp-filesystem/CVE-2025-53109 --build --rounds 1
```

Set `--rounds` to `3` for repeated validation. Add `--offline` when all required inputs are already cached locally.

## Repository Guide

- [Environment index](docs/environments.md): Browse environments by product and CVE/GHSA
- [Environment registry](environments.toml): Machine-readable environment list
- [Reproduction workflow](docs/reproduction-workflow.md): Build, run, and validation steps
- [Environment contract](docs/environment-contract.md): Input, isolation, evidence, and status rules
- [Contributing guide](CONTRIBUTING.md): Requirements for adding or changing environments
- [Diagram contract](docs/diagram-contract.md): Mechanism diagram fields and checks
- [Architecture decisions](docs/adr/): Recorded toolchain and repository decisions

## Contributing

Read the [contributing guide](CONTRIBUTING.md) before creating an environment or submitting a fix. Keep upstream sources, versions, license information, and fixed hashes, and provide independently checkable reproduction evidence.

Before submitting changes, run:

```sh
python3 -m runner check
python3 -m runner lint
python3 -m unittest discover -s tests -v
```

## Security and Licensing

Run vulnerability environments on an isolated, disposable host or virtual machine. Do not run cases involving host files, privilege escalation, network access, or escapes directly on a daily workstation.

This repository currently has no project-level open-source license. Until a license is added, do not assume that the repository may be copied, modified, or redistributed. Third-party source code and dependencies remain subject to their respective licenses.

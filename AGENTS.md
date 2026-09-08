# Agent Vulhub Maintainer Guide

- This repository stores CVE reproduction environments. Drafts and templates are not verified vulnerabilities.
- Use Python 3.11+ standard-library APIs for the registry tooling. Keep metadata in TOML and Compose definitions in YAML.
- Read `docs/environment-contract.md` before implementing an environment.
- Keep changes inside the selected environment unless the task explicitly concerns shared tooling.
- Do not execute repository-provided PoCs or start containers merely to inspect or index an environment.
- Do not read real host credentials into fixtures or evidence. Use synthetic markers and locally controlled receivers.
- Pin source revisions and record image digests before declaring an environment ready.
- Keep mechanism and end-to-end results separate. A simulated model is not proof of prompt injection success.
- Do not claim a successful reproduction from process exit status alone. Check vulnerable, patched and benign controls.
- Default CI is static and must not run vulnerable services, install vulnerable dependencies, or call model APIs.
- Preserve unrelated work. Use `apply_patch` for manual edits, and stage explicit paths only.
- Run `python3 -m runner check` and `python3 -m unittest discover -s tests -v` for tooling changes.

# Third-Party Licenses And External Notices

Blitz DFIR is an original work licensed under the Apache License 2.0.

Project copyright:

```text
Copyright 2026 Rienart Ryan Ilagan
```

This file documents third-party software that Blitz DFIR depends on, invokes,
or references for integration. It is not legal advice. Before redistributing a
binary bundle that includes third-party tools, verify the exact bundled
versions and include the corresponding upstream license texts.

## Direct Runtime Python Dependencies

These packages are declared in `requirements.txt` and `pyproject.toml`. They
are installed separately by the user or deployment environment and are not
vendored into this repository.

| Package | License | Source | Use |
| --- | --- | --- | --- |
| Pydantic | MIT | https://github.com/pydantic/pydantic | Data models, schema validation, typed configuration. |
| PyYAML | MIT | https://github.com/yaml/pyyaml | YAML case manifest and tool configuration loading. |
| Jinja2 | BSD 3-Clause | https://github.com/pallets/jinja | HTML report templating. |

Common transitive dependencies may be installed by pip depending on resolver
and platform. Notable examples include MarkupSafe for Jinja2 and pydantic-core
for Pydantic. They remain third-party packages governed by their own licenses.

## Build And Development Dependencies

These are used for packaging, tests, linting, type checking, and dependency
audits. They are not required to run Blitz DFIR in production unless the user
chooses to run the developer quality gates.

| Package | License | Source | Declared in |
| --- | --- | --- | --- |
| setuptools | MIT | https://pypi.org/project/setuptools/ | `pyproject.toml` build backend |
| pytest | MIT | https://github.com/pytest-dev/pytest | `requirements-dev.txt`, `pyproject.toml` dev extra |
| ruff | MIT | https://github.com/astral-sh/ruff | `requirements-dev.txt` |
| mypy | MIT | https://github.com/python/mypy | `requirements-dev.txt` |
| pip-audit | Apache 2.0 | https://github.com/pypa/pip-audit | `requirements-dev.txt` |
| types-PyYAML | Apache 2.0 | https://pypi.org/project/types-PyYAML/ | `requirements-dev.txt` |

## Python Standard Library

Blitz DFIR uses Python standard library modules such as `sqlite3`, `hashlib`,
`subprocess`, `pathlib`, `json`, `uuid`, `datetime`, `logging`, `argparse`,
`csv`, and `zipfile`. These are part of CPython, which is distributed under
the Python Software Foundation License. They are not third-party package
dependencies of Blitz DFIR.

## External Forensic Tools

Blitz DFIR invokes these tools as isolated external subprocesses with argument
arrays. They are not bundled, modified, linked, or redistributed by this
repository. The user's SIFT Workstation or lab environment supplies them.

| Tool | License | Source | Use |
| --- | --- | --- | --- |
| Plaso / log2timeline / psort | Apache 2.0 | https://github.com/log2timeline/plaso | E01/DD timeline generation and PLASO sorting. |
| Volatility 3 | Volatility Software License 1.0 | https://github.com/volatilityfoundation/volatility3 | Memory image triage. |
| Chainsaw | MIT | https://github.com/WithSecureLabs/chainsaw | EVTX detection and triage. |
| Wireshark / tshark | GPLv2 or later | https://www.wireshark.org | PCAP/network triage. |
| YARA | BSD 3-Clause | https://github.com/VirusTotal/yara | Pattern/rule matching against evidence. |
| The Sleuth Kit (`fls`, `mmls`, `icat`) | Mixed: IBM Public License 1.0, CPL 1.0, LGPL 2.1, BSD | https://www.sleuthkit.org/sleuthkit | Disk image filesystem triage fallback. |
| GNU Binutils `strings` | GPLv3 or later | https://www.gnu.org/software/binutils | Bounded string extraction. |

The GPL licenses for `tshark` and GNU `strings` apply to those external
programs. Blitz DFIR does not incorporate or redistribute those binaries. If a
future Blitz package includes those binaries, that package must satisfy the
GPL obligations for the included binaries independently.

## External Agent And Workflow Integrations

These are optional integration paths or local runtimes. They are not bundled
with Blitz DFIR.

| Integration | License / terms posture | Source | Blitz posture |
| --- | --- | --- | --- |
| SANS SIFT Workstation | SANS distribution plus bundled open-source tool licenses | https://www.sans.org/tools/sift-workstation | External forensic environment; not bundled or modified. |
| Protocol SIFT | Verify upstream license before copying or redistributing its files | https://github.com/teamdfir/protocol-sift | Referenced as an external workflow/integration path only. |
| Claude Code | Anthropic terms | https://www.anthropic.com/claude-code | Optional external agent client; not bundled. |
| OpenClaw | MIT for the `openclaw/openclaw` project when that project is used | https://github.com/openclaw/openclaw | Optional external agent client; not bundled. |
| Ollama | MIT | https://github.com/ollama/ollama | Optional local OpenAI-compatible model runtime; not bundled. |
| Model Context Protocol | MIT for the public specification repositories | https://modelcontextprotocol.io | Blitz implements a typed MCP-compatible server surface; SDKs are not bundled. |

Protocol SIFT note: Blitz DFIR documentation and audit records reference
Protocol SIFT because Blitz is designed to fit that SIFT-oriented agent
workflow. That reference does not make Protocol SIFT a dependency of this
repository. If Protocol SIFT scripts, templates, skills, or documentation are
copied into a future Blitz distribution, add the upstream license text and
attribution at that time.

## License Compatibility Summary

| Category | Compatibility posture with Blitz Apache 2.0 license |
| --- | --- |
| MIT, BSD 3-Clause, Apache 2.0 Python packages | Compatible permissive dependencies. |
| Volatility 3 | External subprocess invocation; comply with upstream license when installing or redistributing Volatility. |
| GPL forensic tools (`tshark`, GNU `strings`) | External subprocess invocation only; Blitz's Apache 2.0 license is not changed unless those binaries are bundled with Blitz. |
| SIFT Workstation and Protocol SIFT | External environment/workflow references; do not redistribute their material without confirming their current license or permission. |
| Claude Code, Anthropic services, API models | External terms govern the user's use of those services; Blitz does not bundle them. |

Last reviewed: 2026-06-14.

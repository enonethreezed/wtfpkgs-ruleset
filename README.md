# wtfpkgs-ruleset

Detection rules for package manager supply chain attacks, derived from the technique catalog at [WTFpkg](https://github.com/0xv1n/WTFpkg).

Covers **27 techniques** across 6 package managers (APT, Homebrew, Cargo, RubyGems, npm, pip) in five rule formats: Sigma, YARA, Splunk ES, Elastic Security, and Microsoft Sentinel.

---

## Structure

```
wtfpkgs-ruleset/
├── techniques-reference.md   # Full technique catalog with detection artifacts and ATT&CK mapping
├── sigma/                    # 11 Sigma rules (SigmaHQ format)
├── yara/                     # 6 YARA rules + scan helper (Yara-Rules format)
├── splunk/                   # 5 Splunk ES detections (splunk/security_content format)
├── elastic/                  # 5 Elastic Security rules (elastic/detection-rules TOML format)
└── sentinel/                 # 5 Microsoft Sentinel analytics (Azure/Azure-Sentinel format)
```

---

## Technique Coverage

| ID | Package Manager | Technique | Sigma | YARA | Splunk | Elastic | Sentinel |
|----|----------------|-----------|:-----:|:----:|:------:|:-------:|:--------:|
| APT-01 | apt | GPG Verification Bypass | ✓ | ✓ | ✓ | — | ✓ |
| APT-02 | apt | Malicious Source Injection | ✓ | ✓ | — | — | ✓ |
| APT-03 | apt | Package Name/Version Spoofing | — | — | — | — | — |
| APT-04 | apt | preinst/postinst Script Execution | ✓ | ✓ | ✓ | ✓ | ✓ |
| APT-05 | apt | Repository MITM (HTTP) | — | — | — | — | — |
| BREW-01 | brew | Cask Flight Block Execution | ✓ | — | — | — | — |
| BREW-02 | brew | Cask pkg Privilege Escalation | ✓ | — | — | — | — |
| BREW-03 | brew | Formula install Ruby Execution | ✓ | — | — | — | — |
| BREW-04 | brew | Malicious Third-Party Tap | ✓ | — | — | — | — |
| CARGO-01 | cargo | build.rs Script Execution | ✓ | ✓ | ✓ | ✓ | ✓ |
| CARGO-02 | cargo | Crate Extraction Attacks | — | — | — | — | — |
| CARGO-03 | cargo | cargo install --git Unpinned | ✓ | — | — | — | — |
| CARGO-04 | cargo | Proc-Macro Compile-Time Execution | ✓ | ✓ | ✓ | ✓ | ✓ |
| GEM-01 | gem | Gemspec Extensions (Rakefile) | ✓ | ✓ | — | ✓ | ✓ |
| GEM-02 | gem | Install Hook Abuse (rubygems_plugin.rb) | ✓ | ✓ | — | ✓ | ✓ |
| GEM-03 | gem | Native Extension (extconf.rb) | ✓ | ✓ | — | ✓ | ✓ |
| GEM-04 | gem | Source Manipulation | — | — | — | — | — |
| NPM-01 | npm | Dependency Confusion | — | — | — | — | — |
| NPM-02 | npm | Lifecycle Script Abuse | ✓ | ✓ | ✓ | ✓ | ✓ |
| NPM-03 | npm | .npmrc Manipulation | — | ✓ | — | — | — |
| NPM-04 | npm | npx Remote Execution | ✓ | — | — | — | — |
| NPM-05 | npm | Package Hijacking | — | — | — | — | — |
| PIP-01 | pip | cmdclass Override | ✓ | ✓ | ✓ | ✓ | ✓ |
| PIP-02 | pip | Dependency Confusion | — | — | — | — | — |
| PIP-03 | pip | requirements.txt Index Manipulation | ✓ | ✓ | — | — | — |
| PIP-04 | pip | setup.py Arbitrary Code Execution | ✓ | ✓ | ✓ | ✓ | ✓ |
| PIP-05 | pip | Typosquatting | — | ✓ | — | — | — |

Gaps (—) indicate techniques better detected through policy controls or pre-install review rather than runtime telemetry. See [techniques-reference.md](techniques-reference.md) for full context.

---

## Rules

### Sigma (`sigma/`)

Format follows [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma). All rules use `ParentCommandLine`/`ParentImage` to anchor detections to package manager process trees and include `filter_*` blocks to exclude known-legitimate compiler and system administration activity.

| File | Technique | Platform | Level |
|------|-----------|----------|-------|
| `proc_creation_lnx_apt_maintainer_script_suspicious_child.yml` | APT-04 | linux | high |
| `proc_creation_lnx_apt_unauthenticated_install.yml` | APT-01 | linux | high |
| `file_event_lnx_apt_source_injection.yml` | APT-02 | linux | medium |
| `proc_creation_lnx_pip_setup_suspicious_child.yml` | PIP-01, PIP-04 | linux | high |
| `file_event_multi_pip_requirements_index_manipulation.yml` | PIP-03 | linux | medium |
| `proc_creation_multi_npm_lifecycle_script_exec.yml` | NPM-02 | linux | high |
| `proc_creation_multi_npx_unversioned_execution.yml` | NPM-04 | linux | medium |
| `proc_creation_lnx_cargo_build_script_network.yml` | CARGO-01, CARGO-04 | linux | high |
| `proc_creation_lnx_cargo_install_git_unpinned.yml` | CARGO-03 | linux | medium |
| `proc_creation_lnx_gem_extension_suspicious_exec.yml` | GEM-01, GEM-02, GEM-03 | linux | high |
| `proc_creation_mac_brew_formula_suspicious_net.yml` | BREW-01, BREW-02, BREW-03 | macos | high |

Convert to your SIEM with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
sigma convert -t splunk sigma/proc_creation_lnx_apt_maintainer_script_suspicious_child.yml
sigma convert -t elasticsearch-eql sigma/proc_creation_lnx_apt_maintainer_script_suspicious_child.yml
sigma convert -t sentinelasim sigma/proc_creation_lnx_apt_maintainer_script_suspicious_child.yml
```

### YARA (`yara/`)

Format follows [Yara-Rules/rules](https://github.com/Yara-Rules/rules). Rules require 2–3 simultaneous conditions to fire and use `not 1 of ($fp_*)` blocks to exclude known-legitimate hosts and patterns. Applied to package source files at rest (before or after install).

| File | Techniques | Rules |
|------|------------|-------|
| `wtfpkg_pip.yar` | PIP-01, PIP-03, PIP-04, PIP-05 | 4 |
| `wtfpkg_npm.yar` | NPM-02, NPM-03 | 3 |
| `wtfpkg_cargo.yar` | CARGO-01, CARGO-04 | 3 |
| `wtfpkg_gem.yar` | GEM-01, GEM-02, GEM-03 | 3 |
| `wtfpkg_apt.yar` | APT-01, APT-02, APT-04 | 4 |

Scan a directory or archive:

```bash
# Using the included helper
yara/wtfpkg-scan.sh /path/to/unpacked/package/

# Single rule file
yara yara/wtfpkg_pip.yar suspicious_package/setup.py

# All rule files at once
yara yara/wtfpkg_pip.yar yara/wtfpkg_npm.yar yara/wtfpkg_cargo.yar \
     yara/wtfpkg_gem.yar yara/wtfpkg_apt.yar /path/to/scan/
```

Typical targets: unpacked `.whl`, `.gem`, `.crate`, `.deb`, or `node_modules/` directories.

### Splunk ES (`splunk/`)

Format follows [splunk/security_content](https://github.com/splunk/security_content). All rules use `tstats` against the CIM `Endpoint.Processes` data model with `security_content_summariesonly`, `drop_dm_object_name`, and `security_content_ctime` macros.

**Requirements:** Endpoint telemetry with full command-line logging mapped to the Splunk CIM (Sysmon for Linux, CrowdStrike, Elastic Endpoint, or equivalent).

| File | Techniques | Risk Score |
|------|------------|-----------|
| `linux_apt_maintainer_script_suspicious_child.yml` | APT-04 | 72 |
| `linux_apt_unauthenticated_install.yml` | APT-01 | 60 |
| `linux_pip_setup_py_network_spawn.yml` | PIP-01, PIP-04 | 68 |
| `linux_npm_lifecycle_script_network_exec.yml` | NPM-02 | 60 |
| `linux_cargo_build_script_suspicious_child.yml` | CARGO-01, CARGO-04 | 68 |

Import into Splunk Enterprise Security via **Content Management → Import** or copy the `search` field directly into a new correlation search.

### Elastic Security (`elastic/`)

Format follows [elastic/detection-rules](https://github.com/elastic/detection-rules) (TOML). All rules use EQL with `sequence by host.id` where applicable to correlate parent and child process events within a bounded time window, reducing false positives in busy CI/CD environments.

**Requirements:** Elastic Endpoint integration or Auditd Manager. Indices: `logs-endpoint.events.process*`, `endgame-*`, `auditbeat-*`.

| File | Techniques | Query Type | Severity |
|------|------------|-----------|----------|
| `initial_access_apt_maintainer_script_spawn.toml` | APT-04 | EQL process | high |
| `initial_access_pip_setup_py_network.toml` | PIP-01, PIP-04 | EQL sequence (10s) | high |
| `initial_access_npm_lifecycle_script_exec.toml` | NPM-02 | EQL sequence (15s) | high |
| `initial_access_cargo_build_script_network.toml` | CARGO-01, CARGO-04 | EQL process | high |
| `initial_access_gem_extension_suspicious_exec.toml` | GEM-01, GEM-02, GEM-03 | EQL sequence (30s) | high |

Load with the elastic-detection-rules CLI:

```bash
pip install detection-rules
python -m detection_rules import-rules-to-repo elastic/
```

Or upload directly via Kibana: **Security → Rules → Import**.

### Microsoft Sentinel (`sentinel/`)

Format follows [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel). All rules are `Scheduled` analytics with `entityMappings`, `customDetails`, and `alertDetailsOverride` for enriched incident creation.

**Requirements:** Microsoft Defender for Endpoint (`DeviceProcessEvents`, `DeviceFileEvents`). The APT source injection rule also queries `DeviceFileEvents`.

| File | Techniques | Severity |
|------|------------|----------|
| `apt_maintainer_script_suspicious_child.yaml` | APT-04 | High |
| `apt_gpg_bypass_and_source_injection.yaml` | APT-01, APT-02 | Medium |
| `python_npm_package_manager_network_spawn.yaml` | PIP-01, PIP-04, NPM-02 | High |
| `cargo_build_script_network_spawn.yaml` | CARGO-01, CARGO-04 | High |
| `gem_extension_hook_suspicious_exec.yaml` | GEM-01, GEM-02, GEM-03 | High |

Deploy via Azure portal (**Sentinel → Analytics → Import**) or with the ARM template CLI:

```bash
az sentinel alert-rule create \
  --resource-group <rg> \
  --workspace-name <workspace> \
  --rule-object @sentinel/apt_maintainer_script_suspicious_child.yaml
```

---

## ATT&CK Coverage

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Supply Chain Compromise: Dev Tools | T1195.001 |
| Execution | Unix Shell | T1059.004 |
| Execution | Python | T1059.006 |
| Execution | JavaScript | T1059.007 |
| Persistence | Launch Agent | T1543.001 |
| Persistence | Launch Daemon | T1543.004 |
| Persistence | Cron | T1053.003 |
| Persistence | Event Triggered Execution | T1546 |
| Defense Evasion | Impair Defenses: Disable Crypto | T1562.001 |
| Defense Evasion | Masquerading | T1036 |
| Credential Access | Credentials In Files | T1552.001 |

---

## Design Principles

Rules are written to avoid generic detections that flood analysts with noise:

- **Process tree anchoring** — Sigma and Splunk rules require `ParentImage`/`ParentCommandLine` to match the package manager context, not just the child process name.
- **Multi-condition YARA** — Every YARA rule requires 2–3 simultaneous indicators. Single-string rules are not included.
- **EQL sequences** — Elastic rules use `sequence by host.id` with time bounds to correlate install context with child process, rather than firing on any shell spawn.
- **Known-good exclusions** — All rules carry explicit filters for legitimate compilation tools (gcc, make, pkg-config, node-gyp), system administration commands (ldconfig, update-alternatives), and known CDNs where applicable.
- **Command line discrimination** — npm and pip rules require network indicators (HTTP URLs, `/dev/tcp`, base64 patterns) in the child process command line, not just the process name.

---

## Technique Reference

[techniques-reference.md](techniques-reference.md) contains the full technique catalog: attack prerequisites, payload patterns, observable artifacts, detection commands, and mitigations for all 27 techniques.

---

## Source

Techniques derived from [WTFpkg](https://github.com/0xv1n/WTFpkg) by 0xv1n.  
Rule formats follow [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), [Yara-Rules/rules](https://github.com/Yara-Rules/rules), [splunk/security_content](https://github.com/splunk/security_content), [elastic/detection-rules](https://github.com/elastic/detection-rules), and [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel).

Contributions welcome — see open gaps in the coverage table above.

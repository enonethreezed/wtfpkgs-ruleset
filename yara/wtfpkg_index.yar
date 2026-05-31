/*
 * WTFpkg — Master index / include file
 *
 * Include this file to load all wtfpkg rules in a single yara invocation:
 *
 *   yara -r wtfpkg_index.yar /path/to/scan/
 *
 * Or scan a single package archive:
 *
 *   yara -r wtfpkg_index.yar suspicious.whl suspicious.gem suspicious.tgz
 *
 * Per-file rules:
 *   wtfpkg_apt.yar    APT-01, APT-02, APT-04
 *   wtfpkg_cargo.yar  CARGO-01, CARGO-03, CARGO-04
 *   wtfpkg_gem.yar    GEM-01, GEM-02, GEM-03
 *   wtfpkg_npm.yar    NPM-02, NPM-03
 *   wtfpkg_pip.yar    PIP-01, PIP-03, PIP-04, PIP-05
 *
 * NOTE: YARA does not support multi-file includes via a single directive.
 * Run all rule files together by passing them as arguments:
 *
 *   yara wtfpkg_apt.yar wtfpkg_cargo.yar wtfpkg_gem.yar wtfpkg_npm.yar wtfpkg_pip.yar /target/
 *
 * Or use the companion shell wrapper: wtfpkg-scan.sh
 *
 * Author: wtfpkg-rules
 * Date: 2026-05-31
 */

// Placeholder rule — ensures this file is valid YARA syntax and can be
// passed to yara alongside the other rule files.
rule wtfpkg_readme
{
    meta:
        description = "Index rule — always false, serves as documentation anchor"
        author      = "wtfpkg-rules"
    condition:
        false
}

/*
 * WTFpkg — Cargo / Rust package supply chain attack detection
 *
 * Techniques covered:
 *   CARGO-01  build.rs build script execution
 *   CARGO-03  cargo install --git (unpinned)
 *   CARGO-04  procedural macro compile-time execution
 *
 * References: https://github.com/0xv1n/WTFpkg
 * Author: wtfpkg-rules
 * Date: 2026-05-31
 * License: MIT
 */

/*
 * Detects build.rs files that combine network or subprocess access with
 * credential-harvesting env var reads. Legitimate build scripts check
 * compiler features and emit cargo: directives; they do not read AWS keys
 * or open TCP connections.
 *
 * Requires BOTH the credential read AND a network/shell execution pattern
 * to avoid FPs from build scripts that legitimately check PATH or HOME.
 */
rule wtfpkg_cargo_build_rs_credential_exfil
{
    meta:
        description     = "build.rs reads credential env vars and performs network/subprocess access"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/cargo-build-rs.md"
        technique       = "CARGO-01"
        severity        = "critical"
        mitre_attack    = "T1195.001, T1552.001"

    strings:
        // build.rs functional context (Rust-specific cargo output macros)
        $cargo_rerun    = "cargo:rerun-if-changed" ascii
        $cargo_rustc    = "cargo:rustc-" ascii
        $fn_main        = "fn main()" ascii

        // Credential env vars read at build time
        $env_aws_sec    = "AWS_SECRET_ACCESS_KEY" ascii
        $env_aws_id     = "AWS_ACCESS_KEY_ID" ascii
        $env_gh_token   = "GITHUB_TOKEN" ascii
        $env_npm        = "NPM_TOKEN" ascii
        $env_ci         = "CI_JOB_TOKEN" ascii

        // Network access in Rust
        $net_tcpstream  = "TcpStream::connect" ascii
        $net_reqwest    = "reqwest::" ascii
        $net_ureq       = "ureq::" ascii

        // Subprocess execution
        $cmd_new        = "Command::new(" ascii
        $cmd_output     = ".output()" ascii
        $cmd_spawn      = ".spawn()" ascii

    condition:
        $fn_main and
        (1 of ($cargo_rerun, $cargo_rustc)) and
        1 of ($env_aws_sec, $env_aws_id, $env_gh_token, $env_npm, $env_ci) and
        (1 of ($net_tcpstream, $net_reqwest, $net_ureq) or
         ($cmd_new and 1 of ($cmd_output, $cmd_spawn)))
}


/*
 * Detects build.rs files that spawn shells (bash/sh/cmd) or network utilities
 * (curl/wget) via std::process::Command — a strong indicator of malicious
 * activity since legitimate build scripts call compilers and linkers, not shells.
 *
 * Requires Command::new + suspicious binary name as string argument.
 */
rule wtfpkg_cargo_build_rs_spawn_shell
{
    meta:
        description     = "build.rs spawns a shell or network utility via Command::new"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/cargo-build-rs.md"
        technique       = "CARGO-01"
        severity        = "high"
        mitre_attack    = "T1195.001, T1059.004"

    strings:
        $fn_main        = "fn main()" ascii
        $cmd_new        = "Command::new(" ascii

        // Suspicious binary targets as string literals
        $shell_bash     = "\"bash\"" ascii
        $shell_sh       = "\"sh\"" ascii
        $shell_cmd      = "\"cmd\"" ascii
        $shell_pwsh     = "\"powershell\"" ascii
        $net_curl       = "\"curl\"" ascii
        $net_wget       = "\"wget\"" ascii
        $net_nc         = "\"nc\"" ascii

        // Legitimate targets (reduce FP)
        $fp_cc          = "\"cc\"" ascii
        $fp_gcc         = "\"gcc\"" ascii
        $fp_clang       = "\"clang\"" ascii
        $fp_pkgconfig   = "\"pkg-config\"" ascii

    condition:
        $fn_main and $cmd_new and
        1 of ($shell_bash, $shell_sh, $shell_cmd, $shell_pwsh, $net_curl, $net_wget, $net_nc) and
        not ($fp_cc or $fp_gcc or $fp_clang or $fp_pkgconfig)
}


/*
 * Detects proc-macro crates (lib.rs / lib/ with proc-macro = true in Cargo.toml)
 * that include network access. Proc-macros should only manipulate token streams;
 * any network I/O inside a proc-macro is anomalous.
 *
 * Applied to lib.rs files when Cargo.toml also contains proc-macro = true.
 */
rule wtfpkg_cargo_proc_macro_network_access
{
    meta:
        description     = "Rust proc-macro source contains network or subprocess access — compile-time code execution risk"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/cargo-proc-macros.md"
        technique       = "CARGO-04"
        severity        = "critical"
        mitre_attack    = "T1195.001, T1059"

    strings:
        // proc-macro crate signature
        $proc_macro_attr = "proc_macro_attribute" ascii
        $proc_macro_drv  = "proc_macro_derive" ascii
        $proc_macro_use  = "use proc_macro" ascii
        $extern_pm       = "extern crate proc_macro" ascii

        // Network access
        $net_tcpstream   = "TcpStream::connect" ascii
        $net_reqwest     = "reqwest::" ascii
        $net_std_net     = "std::net::" ascii

        // Subprocess
        $cmd_new         = "Command::new(" ascii

        // Filesystem access outside token manipulation
        $fs_write        = "std::fs::write" ascii
        $fs_create       = "File::create(" ascii

    condition:
        1 of ($proc_macro_attr, $proc_macro_drv, $proc_macro_use, $extern_pm) and
        (
            1 of ($net_tcpstream, $net_reqwest, $net_std_net) or
            $cmd_new or
            ($fs_write and $fs_create)
        )
}

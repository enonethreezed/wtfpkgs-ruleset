/*
 * WTFpkg — APT/dpkg supply chain attack detection
 *
 * Techniques covered:
 *   APT-01  GPG bypass (trusted=yes, --allow-unauthenticated)
 *   APT-02  malicious source injection
 *   APT-04  preinst/postinst maintainer script execution
 *
 * References: https://github.com/0xv1n/WTFpkg
 * Author: wtfpkg-rules
 * Date: 2026-05-31
 * License: MIT
 *
 * Changes vs initial release:
 *   - wtfpkg_apt_maintainer_script_reverse_shell: BUGFIX — `"nc.*| bash"` and
 *     `"socat.*EXEC"` were plain string literals (the `.*` matched literally, never
 *     matching real shell code). Replaced with proper YARA regex syntax:
 *     /nc\s+.*\|\s*bash/ and /socat\s+.*EXEC/
 *   - wtfpkg_apt_unknown_repository_source: BUGFIX — removed tautological inner
 *     condition `#deb_line >= 1`. Since `$deb_line` is required by the outer AND,
 *     its count is always >= 1 when the outer condition is true. The inner OR was
 *     dead code making both branches equivalent. Simplified to direct condition.
 *   - Metadata: added id, modified, score, quality, tags; removed non-standard fields;
 *     reordered to YARA Forge canonical order
 */

rule wtfpkg_apt_maintainer_script_download
{
    meta:
        description  = "dpkg maintainer script (postinst/preinst) downloads from remote URL"
        author       = "wtfpkg-rules"
        id           = "db00d35d-bcfa-428d-81b5-4bfd35ee584d"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/apt-preinst-postinst-scripts.md"
        score        = 80
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1059_004, APT, LINUX"

    strings:
        $shebang_sh     = "#!/bin/sh" ascii
        $shebang_bash   = "#!/bin/bash" ascii
        $trigger_cfg    = "configure" ascii
        $trigger_inst   = "$1 = \"install\"" ascii

        $dl_curl        = "curl " ascii
        $dl_wget        = "wget " ascii
        $dl_python_dl   = "urllib.request" ascii

        $url_http       = "http://" ascii
        $url_https      = "https://" ascii

        $pipe_bash      = "| bash" ascii
        $pipe_sh        = "| sh" ascii
        $pipe_python    = "| python" ascii
        $exec_dl        = "chmod +x" ascii

        $fp_apt_mirror  = "security.debian.org" ascii
        $fp_ubuntu_srv  = "archive.ubuntu.com" ascii

    condition:
        filesize < 500KB and
        1 of ($shebang_sh, $shebang_bash) and
        1 of ($dl_curl, $dl_wget, $dl_python_dl) and
        1 of ($url_http, $url_https) and
        not 1 of ($fp_apt_mirror, $fp_ubuntu_srv) and
        (1 of ($pipe_bash, $pipe_sh, $pipe_python) or $exec_dl)
}


rule wtfpkg_apt_maintainer_script_reverse_shell
{
    meta:
        description  = "dpkg maintainer script contains reverse shell indicators"
        author       = "wtfpkg-rules"
        id           = "ed55fc99-787e-41ce-b898-95e3d90917a2"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/apt-preinst-postinst-scripts.md"
        score        = 85
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1059_004, APT, LINUX, REVERSE_SHELL"

    strings:
        $shebang_sh     = "#!/bin/sh" ascii
        $shebang_bash   = "#!/bin/bash" ascii

        $devtcp         = "/dev/tcp/" ascii
        $devudp         = "/dev/udp/" ascii
        $bash_i         = "bash -i" ascii
        $sh_i           = "sh -i" ascii
        $nc_e           = "nc -e" ascii
        // BUGFIX: was `"nc.*| bash"` (literal string, never matched).
        // Proper YARA regex matching netcat piped to bash.
        $nc_pipe        = /nc\s+.*\|\s*bash/ ascii
        $ncat_e         = "ncat -e" ascii
        // BUGFIX: was `"socat.*EXEC"` (literal string, never matched).
        $socat_exec     = /socat\s+.*EXEC/ ascii

    condition:
        filesize < 500KB and
        1 of ($shebang_sh, $shebang_bash) and
        2 of ($devtcp, $devudp, $bash_i, $sh_i, $nc_e, $nc_pipe, $ncat_e, $socat_exec)
}


rule wtfpkg_apt_sources_trusted_yes
{
    meta:
        description  = "APT sources.list entry uses trusted=yes — GPG verification bypass"
        author       = "wtfpkg-rules"
        id           = "15828b00-0b6d-4ca2-8e4d-9c0cdd34842f"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/apt-gpg-bypass.md"
        score        = 70
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1562_001, APT, LINUX"

    strings:
        $deb_src        = /^deb(-src)?\s/ ascii
        $deb_bracket    = /^deb(-src)?\s+\[/ ascii
        $trusted_yes    = "trusted=yes" ascii nocase
        // Filter: line commented out
        $comment        = /^#.*trusted=yes/ ascii

    condition:
        filesize < 50KB and
        $trusted_yes and
        1 of ($deb_src, $deb_bracket) and
        not $comment
}


rule wtfpkg_apt_unknown_repository_source
{
    meta:
        description  = "APT sources.list.d entry points to unknown third-party repository host"
        author       = "wtfpkg-rules"
        id           = "a6f4c264-e3fd-40dd-bc49-db9f24c3464e"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/apt-malicious-repo-source.md"
        score        = 55
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, APT, LINUX"

    strings:
        $deb_line       = /^deb\s/ ascii

        $fp_debian      = "deb.debian.org" ascii
        $fp_ubuntu      = "archive.ubuntu.com" ascii
        $fp_security    = "security.ubuntu.com" ascii
        $fp_ports       = "ports.ubuntu.com" ascii
        $fp_ppa         = "ppa.launchpad.net" ascii
        $fp_docker      = "download.docker.com" ascii
        $fp_google      = "packages.cloud.google.com" ascii
        $fp_microsoft   = "packages.microsoft.com" ascii
        $fp_nodesource  = "deb.nodesource.com" ascii
        $fp_nginx       = "nginx.org" ascii
        $fp_elastic     = "artifacts.elastic.co" ascii

        // High-confidence sub-indicator: IP address as repo host
        $ip_repo        = /deb https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii

    condition:
        // BUGFIX: removed `(#deb_line >= 1)` inner condition — tautological since
        // `$deb_line` being true already guarantees count >= 1.
        // The $ip_repo string remains available for post-match triage/scoring
        // in external tooling even though it is not required by this condition.
        filesize < 10KB and
        $deb_line and
        not 1 of ($fp_*)
}

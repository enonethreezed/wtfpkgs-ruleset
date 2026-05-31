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
 */

/*
 * Detects Debian maintainer scripts (postinst, preinst, etc.) that contain
 * network download patterns combined with remote URL indicators.
 * Legitimate maintainer scripts configure daemons, run ldconfig, update
 * alternatives — they do not download from the internet.
 *
 * Requires BOTH a download utility AND an HTTP/S URL to reduce FPs from
 * scripts that use curl/wget for local socket interactions.
 */
rule wtfpkg_apt_maintainer_script_download
{
    meta:
        description     = "dpkg maintainer script (postinst/preinst) downloads from remote URL"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/apt-preinst-postinst-scripts.md"
        technique       = "APT-04"
        severity        = "critical"
        mitre_attack    = "T1195.001, T1059.004"

    strings:
        // Maintainer script shebang / context
        $shebang_sh     = "#!/bin/sh" ascii
        $shebang_bash   = "#!/bin/bash" ascii
        // dpkg state trigger strings
        $trigger_cfg    = "configure" ascii
        $trigger_inst   = "$1 = \"install\"" ascii

        // Download utilities
        $dl_curl        = "curl " ascii
        $dl_wget        = "wget " ascii
        $dl_python_dl   = "urllib.request" ascii

        // Remote URL indicators (not loopback)
        $url_http       = "http://" ascii
        $url_https      = "https://" ascii

        // Shell execution of downloaded content
        $pipe_bash      = "| bash" ascii
        $pipe_sh        = "| sh" ascii
        $pipe_python    = "| python" ascii
        $exec_dl        = "chmod +x" ascii

        // Legitimate patterns to reduce FP
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


/*
 * Detects maintainer scripts that establish reverse shells.
 * Three-way requirement: shell context + /dev/tcp or netcat + interactive
 * flag or pipe-to-shell — highly specific combination with very low FP rate.
 */
rule wtfpkg_apt_maintainer_script_reverse_shell
{
    meta:
        description     = "dpkg maintainer script contains reverse shell indicators"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/apt-preinst-postinst-scripts.md"
        technique       = "APT-04"
        severity        = "critical"
        mitre_attack    = "T1195.001, T1059.004"

    strings:
        $shebang_sh     = "#!/bin/sh" ascii
        $shebang_bash   = "#!/bin/bash" ascii

        // Reverse shell indicators
        $devtcp         = "/dev/tcp/" ascii
        $devudp         = "/dev/udp/" ascii
        $bash_i         = "bash -i" ascii
        $sh_i           = "sh -i" ascii
        $nc_e           = "nc -e" ascii
        $nc_pipe        = "nc.*| bash" ascii
        $ncat_e         = "ncat -e" ascii
        $socat_exec     = "socat.*EXEC" ascii

    condition:
        filesize < 500KB and
        1 of ($shebang_sh, $shebang_bash) and
        2 of ($devtcp, $devudp, $bash_i, $sh_i, $nc_e, $nc_pipe, $ncat_e, $socat_exec)
}


/*
 * Detects APT sources.list entries or sources.list.d files that include
 * the trusted=yes option, which disables GPG signature verification for
 * the declared repository.
 *
 * Requires the deb/deb-src line format AND trusted=yes to be present,
 * avoiding false positives from documentation or comment lines.
 */
rule wtfpkg_apt_sources_trusted_yes
{
    meta:
        description     = "APT sources.list entry uses trusted=yes — GPG verification bypass"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/apt-gpg-bypass.md"
        technique       = "APT-01"
        severity        = "medium"
        mitre_attack    = "T1195.001, T1562.001"

    strings:
        // Active source lines (not commented out)
        $deb_src        = /^deb(-src)?\s/ ascii
        $deb_bracket    = /^deb(-src)?\s+\[/ ascii

        // trusted=yes option
        $trusted_yes    = "trusted=yes" ascii nocase

        // Comment line — used in filter
        $comment        = /^#.*trusted=yes/ ascii

    condition:
        filesize < 50KB and
        $trusted_yes and
        1 of ($deb_src, $deb_bracket) and
        not $comment
}


/*
 * Detects .list files added to /etc/apt/sources.list.d/ that point to
 * non-standard/non-official repository hosts and include persistence
 * mechanisms (e.g., pinning + the repo entry together).
 *
 * The rule flags repos not matching known-legitimate CDNs by requiring
 * the absence of all known-good strings while finding an unusual URI.
 */
rule wtfpkg_apt_unknown_repository_source
{
    meta:
        description     = "APT sources.list.d entry points to unknown third-party repository host"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/apt-malicious-repo-source.md"
        technique       = "APT-02"
        severity        = "low"
        mitre_attack    = "T1195.001"

    strings:
        $deb_line       = /^deb\s/ ascii

        // Known-legitimate repository base domains (non-exhaustive — extend per-org)
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

        // Suspicious: IP address as repository host
        $ip_repo        = /deb https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii

    condition:
        filesize < 10KB and
        $deb_line and
        not 1 of ($fp_*) and
        (
            $ip_repo or
            // File has a deb line but no recognized host — unknown third-party
            #deb_line >= 1
        )
}

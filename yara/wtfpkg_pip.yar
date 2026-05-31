/*
 * WTFpkg — pip / Python package supply chain attack detection
 *
 * Techniques covered:
 *   PIP-01  cmdclass override in setup.py
 *   PIP-03  requirements.txt index manipulation
 *   PIP-04  setup.py arbitrary code execution
 *   PIP-05  typosquatting payload patterns
 *
 * References: https://github.com/0xv1n/WTFpkg
 * Author: wtfpkg-rules
 * Date: 2026-05-31
 * License: MIT
 */

import "hash"

/*
 * Detects setup.py files that combine a cmdclass override with suspicious
 * runtime behaviour (network access or subprocess invocation).
 * Requires ALL THREE conditions to fire — avoids flagging every setup.py
 * that legitimately overrides build_ext for C extension compilation.
 */
rule wtfpkg_pip_cmdclass_override_with_network
{
    meta:
        description     = "setup.py cmdclass override combined with network/subprocess access"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/pip-cmdclass-override.md"
        technique       = "PIP-01"
        severity        = "high"
        mitre_attack    = "T1195.001"

    strings:
        // Must be a setup.py-style file
        $setup_call     = "setup(" ascii
        // cmdclass override — required
        $cmdclass       = "cmdclass" ascii
        // Network access patterns — any one of these is suspicious inside setup.py
        $net_urllib     = "urllib.request" ascii
        $net_requests   = "import requests" ascii
        $net_socket     = "import socket" ascii
        $net_http       = "http.client" ascii
        // Subprocess / shell execution
        $sub_popen      = "subprocess.Popen" ascii
        $sub_call       = "subprocess.call" ascii
        $sub_check      = "subprocess.check_output" ascii
        $os_system      = "os.system(" ascii
        $os_popen       = "os.popen(" ascii

    condition:
        $setup_call and $cmdclass and
        (
            1 of ($net_*) or
            1 of ($sub_*) or
            $os_system or $os_popen
        )
}


/*
 * Detects setup.py performing credential exfiltration patterns:
 * reading common env vars that hold secrets and pairing with network access.
 * Requires the env var access AND a network sink.
 */
rule wtfpkg_pip_setup_credential_exfil
{
    meta:
        description     = "setup.py reads credential env vars and has network access — likely exfiltration"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/pip-setup-py-execution.md"
        technique       = "PIP-04"
        severity        = "critical"
        mitre_attack    = "T1195.001, T1552.001"

    strings:
        // Credential env var names commonly targeted
        $env_aws_key    = "AWS_SECRET_ACCESS_KEY" ascii nocase
        $env_aws_id     = "AWS_ACCESS_KEY_ID" ascii nocase
        $env_gh_token   = "GITHUB_TOKEN" ascii nocase
        $env_npm_token  = "NPM_TOKEN" ascii nocase
        $env_ci_token   = "CI_JOB_TOKEN" ascii nocase
        $env_generic    = "os.environ" ascii

        // Network sink
        $net_urllib     = "urllib.request.urlopen" ascii
        $net_requests   = "requests.post" ascii
        $net_socket_c   = "socket.connect" ascii
        $net_curl       = "curl" ascii
        $net_wget       = "wget" ascii

        // setup.py context (avoids flagging arbitrary Python)
        $setup_ctx      = "setup(" ascii
        $from_sttools   = "from setuptools" ascii

    condition:
        ($setup_ctx or $from_sttools) and
        (1 of ($env_aws_key, $env_aws_id, $env_gh_token, $env_npm_token, $env_ci_token) or
         ($env_generic and #env_generic >= 2)) and
        1 of ($net_*)
}


/*
 * Detects requirements.txt files containing dangerous pip global options
 * that redirect or intercept package downloads.
 * Requires the directive AND an external (non-localhost) URL to avoid
 * flagging legitimate internal proxy configurations documented in comments.
 */
rule wtfpkg_pip_requirements_index_manipulation
{
    meta:
        description     = "requirements.txt contains dangerous index-url/trusted-host directives pointing to external hosts"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/pip-requirements-manipulation.md"
        technique       = "PIP-03"
        severity        = "high"
        mitre_attack    = "T1195.001, T1071.001"

    strings:
        // Dangerous global directives in requirements files
        $idx_url        = "--index-url" ascii
        $extra_idx      = "--extra-index-url" ascii
        $find_links     = "--find-links" ascii
        $trusted_host   = "--trusted-host" ascii

        // External URL indicators (not localhost / 127.x / internal RFC1918)
        $url_http       = "http://" ascii
        $url_https      = "https://" ascii

        // Known-legitimate internal markers (reduce FP for documented proxies)
        $fp_pypi        = "pypi.org" ascii
        $fp_pypi2       = "files.pythonhosted.org" ascii
        $fp_localhost   = "localhost" ascii
        $fp_127         = "127.0.0" ascii

    condition:
        filesize < 50KB and
        1 of ($idx_url, $extra_idx, $find_links, $trusted_host) and
        1 of ($url_http, $url_https) and
        not 1 of ($fp_pypi, $fp_pypi2, $fp_localhost, $fp_127)
}


/*
 * Detects wheel (.whl) or sdist archives where setup.py contains an encoded
 * payload (base64 / hex) paired with a decode+exec pattern — a classic
 * obfuscation used by typosquatting packages to evade naive string scanning.
 */
rule wtfpkg_pip_setup_obfuscated_exec
{
    meta:
        description     = "setup.py contains base64/hex decode combined with exec/eval — obfuscated payload"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/pip-typosquatting.md"
        technique       = "PIP-05"
        severity        = "high"
        mitre_attack    = "T1195.001, T1027"

    strings:
        // Decode functions
        $b64_decode     = "base64.b64decode" ascii
        $b64_decode2    = "b64decode(" ascii
        $hex_decode     = "bytes.fromhex(" ascii
        $codecs_decode  = "codecs.decode(" ascii

        // Execution sinks
        $exec_call      = "exec(" ascii
        $eval_call      = "eval(" ascii
        $compile_call   = "compile(" ascii

        // setup.py context
        $setup_ctx      = "setup(" ascii

    condition:
        $setup_ctx and
        1 of ($b64_decode, $b64_decode2, $hex_decode, $codecs_decode) and
        1 of ($exec_call, $eval_call, $compile_call)
}

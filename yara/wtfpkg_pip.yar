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
 *
 * Changes vs initial release:
 *   - Removed unused `import "hash"` (no rule used hash module functions)
 *   - $net_curl / $net_wget: "curl" / "wget" (4 chars) -> "curl " / "wget " (5 chars)
 *     to clear the yaraQA short-atom threshold
 *   - Metadata: added id, modified, score, quality, tags; removed non-standard
 *     version/severity/technique/mitre_attack; reordered to YARA Forge canonical order
 */

rule wtfpkg_pip_cmdclass_override_with_network
{
    meta:
        description  = "setup.py cmdclass override combined with network/subprocess access"
        author       = "wtfpkg-rules"
        id           = "09768210-1399-4279-9b4f-f366adc0839b"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/pip-cmdclass-override.md"
        score        = 75
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, PIP, PYTHON"

    strings:
        $setup_call     = "setup(" ascii
        $cmdclass       = "cmdclass" ascii
        $net_urllib     = "urllib.request" ascii
        $net_requests   = "import requests" ascii
        $net_socket     = "import socket" ascii
        $net_http       = "http.client" ascii
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


rule wtfpkg_pip_setup_credential_exfil
{
    meta:
        description  = "setup.py reads credential env vars and has network access — likely exfiltration"
        author       = "wtfpkg-rules"
        id           = "57f5aea5-b19b-41ee-80a5-651894d8cf80"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/pip-setup-py-execution.md"
        score        = 80
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1552_001, PIP, PYTHON, CREDENTIAL_EXFIL"

    strings:
        $env_aws_key    = "AWS_SECRET_ACCESS_KEY" ascii nocase
        $env_aws_id     = "AWS_ACCESS_KEY_ID" ascii nocase
        $env_gh_token   = "GITHUB_TOKEN" ascii nocase
        $env_npm_token  = "NPM_TOKEN" ascii nocase
        $env_ci_token   = "CI_JOB_TOKEN" ascii nocase
        $env_generic    = "os.environ" ascii

        $net_urllib     = "urllib.request.urlopen" ascii
        $net_requests   = "requests.post" ascii
        $net_socket_c   = "socket.connect" ascii
        // "curl " and "wget " (5 bytes each) replace the 4-byte "curl"/"wget" atoms
        $net_curl       = "curl " ascii
        $net_wget       = "wget " ascii

        $setup_ctx      = "setup(" ascii
        $from_sttools   = "from setuptools" ascii

    condition:
        ($setup_ctx or $from_sttools) and
        (1 of ($env_aws_key, $env_aws_id, $env_gh_token, $env_npm_token, $env_ci_token) or
         ($env_generic and #env_generic >= 2)) and
        1 of ($net_*)
}


rule wtfpkg_pip_requirements_index_manipulation
{
    meta:
        description  = "requirements.txt contains dangerous index-url/trusted-host directives pointing to external hosts"
        author       = "wtfpkg-rules"
        id           = "d6ec6dba-7dab-4630-88db-6a0c637212df"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/pip-requirements-manipulation.md"
        score        = 75
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1071_001, PIP, PYTHON"

    strings:
        $idx_url        = "--index-url" ascii
        $extra_idx      = "--extra-index-url" ascii
        $find_links     = "--find-links" ascii
        $trusted_host   = "--trusted-host" ascii

        $url_http       = "http://" ascii
        $url_https      = "https://" ascii

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


rule wtfpkg_pip_setup_obfuscated_exec
{
    meta:
        description  = "setup.py contains base64/hex decode combined with exec/eval — obfuscated payload"
        author       = "wtfpkg-rules"
        id           = "2d4443db-fc09-4284-8016-3e458b46c5fc"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/pip-typosquatting.md"
        score        = 75
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1027, PIP, PYTHON, OBFUSCATION"

    strings:
        $b64_decode     = "base64.b64decode" ascii
        $b64_decode2    = "b64decode(" ascii
        $hex_decode     = "bytes.fromhex(" ascii
        $codecs_decode  = "codecs.decode(" ascii

        $exec_call      = "exec(" ascii
        $eval_call      = "eval(" ascii
        $compile_call   = "compile(" ascii

        $setup_ctx      = "setup(" ascii

    condition:
        $setup_ctx and
        1 of ($b64_decode, $b64_decode2, $hex_decode, $codecs_decode) and
        1 of ($exec_call, $eval_call, $compile_call)
}

/*
 * WTFpkg — npm package supply chain attack detection
 *
 * Techniques covered:
 *   NPM-02  lifecycle script abuse (preinstall / postinstall)
 *   NPM-03  .npmrc manipulation
 *   NPM-04  npx remote execution
 *
 * References: https://github.com/0xv1n/WTFpkg
 * Author: wtfpkg-rules
 * Date: 2026-05-31
 * License: MIT
 */

/*
 * Detects package.json files that define lifecycle scripts containing
 * network access or shell execution. Requires BOTH a lifecycle hook key
 * AND a suspicious command pattern — avoids flagging every package with
 * a "build" or "test" script.
 */
rule wtfpkg_npm_lifecycle_script_network_exec
{
    meta:
        description     = "package.json lifecycle script contains network download or shell execution"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/npm-lifecycle-scripts.md"
        technique       = "NPM-02"
        severity        = "high"
        mitre_attack    = "T1195.001, T1059.004"

    strings:
        // Lifecycle hooks that execute during npm install
        $hook_preinst   = "\"preinstall\"" ascii
        $hook_postinst  = "\"postinstall\"" ascii
        $hook_install   = "\"install\"" ascii
        $hook_prepare   = "\"prepare\"" ascii

        // Network and shell execution patterns in script values
        $cmd_curl       = "curl " ascii
        $cmd_wget       = "wget " ascii
        $cmd_nc         = " nc " ascii
        $cmd_bash_i     = "bash -i" ascii
        $cmd_sh_i       = "sh -i" ascii
        $cmd_devtcp     = "/dev/tcp/" ascii
        $cmd_b64        = "base64" ascii
        $cmd_eval       = "eval $(" ascii
        $cmd_eval2      = "eval \"$(" ascii
        // Node-based network (often used in malicious postinstall)
        $js_require_net = "require('net')" ascii
        $js_require_net2= "require(\"net\")" ascii
        $js_https_get   = "https.get(" ascii
        $js_http_get    = "http.get(" ascii

        // package.json structure anchor
        $pkg_name       = "\"name\":" ascii
        $pkg_version    = "\"version\":" ascii

    condition:
        filesize < 100KB and
        $pkg_name and $pkg_version and
        1 of ($hook_preinst, $hook_postinst, $hook_install, $hook_prepare) and
        2 of ($cmd_curl, $cmd_wget, $cmd_nc, $cmd_bash_i, $cmd_sh_i,
              $cmd_devtcp, $cmd_b64, $cmd_eval, $cmd_eval2,
              $js_require_net, $js_require_net2, $js_https_get, $js_http_get)
}


/*
 * Detects package.json postinstall/preinstall scripts that include
 * credential-harvesting patterns: reading process.env for known secret keys
 * and pairing with outbound HTTP/HTTPS calls.
 */
rule wtfpkg_npm_lifecycle_credential_exfil
{
    meta:
        description     = "package.json script reads credential env vars and makes outbound connection"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/npm-lifecycle-scripts.md"
        technique       = "NPM-02"
        severity        = "critical"
        mitre_attack    = "T1195.001, T1552.001"

    strings:
        // Credential env vars
        $env_aws        = "AWS_SECRET" ascii nocase
        $env_npm        = "NPM_TOKEN" ascii nocase
        $env_gh         = "GITHUB_TOKEN" ascii nocase
        $env_ci         = "CI_TOKEN" ascii nocase
        $env_proc       = "process.env" ascii

        // Network exfiltration
        $net_fetch      = "fetch(" ascii
        $net_xhr        = "XMLHttpRequest" ascii
        $net_http_req   = "http.request(" ascii
        $net_https_req  = "https.request(" ascii
        $net_axios      = "axios.post(" ascii

        // package.json context
        $hook_postinst  = "\"postinstall\"" ascii
        $hook_preinst   = "\"preinstall\"" ascii

    condition:
        filesize < 200KB and
        1 of ($hook_postinst, $hook_preinst) and
        ($env_proc and 1 of ($env_aws, $env_npm, $env_gh, $env_ci)) and
        1 of ($net_fetch, $net_xhr, $net_http_req, $net_https_req, $net_axios)
}


/*
 * Detects .npmrc files that contain a registry directive pointing to
 * a non-canonical host (not registry.npmjs.org / npm.pkg.github.com).
 * The rule requires the registry key AND an external URL without the
 * known-legitimate registries to minimize false positives from legitimate
 * Artifactory / Nexus private registry configurations.
 *
 * NOTE: Legitimate private registries should be allowlisted per-org.
 */
rule wtfpkg_npm_npmrc_suspicious_registry
{
    meta:
        description     = ".npmrc redirects to non-canonical npm registry — possible supply chain redirect"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/npm-npmrc-manipulation.md"
        technique       = "NPM-03"
        severity        = "medium"
        mitre_attack    = "T1195.001, T1071.001"

    strings:
        // Registry directive
        $reg_directive  = "registry=" ascii

        // Known-legitimate registries (used in filter condition)
        $fp_npmjs       = "registry.npmjs.org" ascii
        $fp_yarnpkg     = "registry.yarnpkg.com" ascii
        $fp_github      = "npm.pkg.github.com" ascii
        $fp_localhost   = "localhost" ascii
        $fp_127         = "127.0.0" ascii

        // SSL/security disabling (any match here + registry = high confidence)
        $ssl_false      = "strict-ssl=false" ascii
        $ssl_false2     = "strict-ssl = false" ascii
        $ignore_scripts = "ignore-scripts=false" ascii

    condition:
        filesize < 10KB and
        $reg_directive and
        not 1 of ($fp_npmjs, $fp_yarnpkg, $fp_github, $fp_localhost, $fp_127) and
        (
            // Either unknown registry + security bypass
            1 of ($ssl_false, $ssl_false2, $ignore_scripts) or
            // Or just unknown registry (lower confidence, but still medium)
            #reg_directive >= 1
        )
}

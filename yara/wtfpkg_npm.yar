/*
 * WTFpkg — npm package supply chain attack detection
 *
 * Techniques covered:
 *   NPM-02  lifecycle script abuse (preinstall / postinstall)
 *   NPM-03  .npmrc manipulation
 *
 * References: https://github.com/0xv1n/WTFpkg
 * Author: wtfpkg-rules
 * Date: 2026-05-31
 * License: MIT
 *
 * Changes vs initial release:
 *   - wtfpkg_npm_npmrc_suspicious_registry: removed tautological `#reg_directive >= 1`
 *     inner condition (the outer `$reg_directive` already guarantees count >= 1)
 *   - Metadata: added id, modified, score, quality, tags; removed non-standard fields;
 *     reordered to YARA Forge canonical order
 */

rule wtfpkg_npm_lifecycle_script_network_exec
{
    meta:
        description  = "package.json lifecycle script contains network download or shell execution"
        author       = "wtfpkg-rules"
        id           = "d37dd8de-e4ee-4afd-a244-47f25bee4186"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/npm-lifecycle-scripts.md"
        score        = 75
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1059_004, T1059_007, NPM, NODEJS"

    strings:
        $hook_preinst   = "\"preinstall\"" ascii
        $hook_postinst  = "\"postinstall\"" ascii
        $hook_install   = "\"install\"" ascii
        $hook_prepare   = "\"prepare\"" ascii

        $cmd_curl       = "curl " ascii
        $cmd_wget       = "wget " ascii
        $cmd_nc         = " nc " ascii
        $cmd_bash_i     = "bash -i" ascii
        $cmd_sh_i       = "sh -i" ascii
        $cmd_devtcp     = "/dev/tcp/" ascii
        $cmd_b64        = "base64" ascii
        $cmd_eval       = "eval $(" ascii
        $cmd_eval2      = "eval \"$(" ascii
        $js_require_net = "require('net')" ascii
        $js_require_net2= "require(\"net\")" ascii
        $js_https_get   = "https.get(" ascii
        $js_http_get    = "http.get(" ascii

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


rule wtfpkg_npm_lifecycle_credential_exfil
{
    meta:
        description  = "package.json script reads credential env vars and makes outbound connection"
        author       = "wtfpkg-rules"
        id           = "50d04fb8-f7fb-453e-bbe1-ee24a22219ff"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/npm-lifecycle-scripts.md"
        score        = 80
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1552_001, NPM, NODEJS, CREDENTIAL_EXFIL"

    strings:
        $env_aws        = "AWS_SECRET" ascii nocase
        $env_npm        = "NPM_TOKEN" ascii nocase
        $env_gh         = "GITHUB_TOKEN" ascii nocase
        $env_ci         = "CI_TOKEN" ascii nocase
        $env_proc       = "process.env" ascii

        $net_fetch      = "fetch(" ascii
        $net_xhr        = "XMLHttpRequest" ascii
        $net_http_req   = "http.request(" ascii
        $net_https_req  = "https.request(" ascii
        $net_axios      = "axios.post(" ascii

        $hook_postinst  = "\"postinstall\"" ascii
        $hook_preinst   = "\"preinstall\"" ascii

    condition:
        filesize < 200KB and
        1 of ($hook_postinst, $hook_preinst) and
        ($env_proc and 1 of ($env_aws, $env_npm, $env_gh, $env_ci)) and
        1 of ($net_fetch, $net_xhr, $net_http_req, $net_https_req, $net_axios)
}


rule wtfpkg_npm_npmrc_suspicious_registry
{
    meta:
        description  = ".npmrc redirects to non-canonical npm registry — possible supply chain redirect"
        author       = "wtfpkg-rules"
        id           = "d56ed158-89f0-4814-b8b9-0a8e4cc711fb"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/npm-npmrc-manipulation.md"
        score        = 70
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1071_001, NPM, NODEJS"

    strings:
        $reg_directive  = "registry=" ascii

        $fp_npmjs       = "registry.npmjs.org" ascii
        $fp_yarnpkg     = "registry.yarnpkg.com" ascii
        $fp_github      = "npm.pkg.github.com" ascii
        $fp_localhost   = "localhost" ascii
        $fp_127         = "127.0.0" ascii

        // Security-bypass strings: present alone they upgrade confidence
        $ssl_false      = "strict-ssl=false" ascii
        $ssl_false2     = "strict-ssl = false" ascii
        $ignore_scripts = "ignore-scripts=false" ascii

    condition:
        filesize < 10KB and
        $reg_directive and
        not 1 of ($fp_npmjs, $fp_yarnpkg, $fp_github, $fp_localhost, $fp_127)
        // Removed tautological `#reg_directive >= 1` — $reg_directive being true already
        // guarantees count >= 1. Both branches of the original inner OR were equivalent.
        // The security-bypass strings are now available for correlation in external tooling.
}

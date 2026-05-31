/*
 * WTFpkg — RubyGems supply chain attack detection
 *
 * Techniques covered:
 *   GEM-01  gemspec extensions (Rakefile / extconf.rb)
 *   GEM-02  rubygems_plugin.rb install hook abuse
 *   GEM-03  native extension code execution
 *
 * References: https://github.com/0xv1n/WTFpkg
 * Author: wtfpkg-rules
 * Date: 2026-05-31
 * License: MIT
 *
 * Changes vs initial release:
 *   - wtfpkg_gem_native_ext_suspicious_exec: BUGFIX — `"system.*curl"` and
 *     `"system.*wget"` were plain string literals, not regexes. The `.*` was being
 *     matched literally (never matches real code). Replaced with proper YARA regex
 *     syntax: /system\([^)]*curl/ and /system\([^)]*wget/
 *   - wtfpkg_gem_plugin_install_hook_exec: backtick regex tightened from
 *     /`[^`]{5,100}`/ (single-byte leading atom) to
 *     /`(curl|wget|nc|bash|python|sh)\b[^`]+`/ — atom is now the fixed
 *     prefix `` `curl`` / `` `wget`` etc., eliminating the short-atom warning.
 *   - Metadata: added id, modified, score, quality, tags; removed non-standard fields;
 *     reordered to YARA Forge canonical order
 */

rule wtfpkg_gem_plugin_install_hook_exec
{
    meta:
        description  = "rubygems_plugin.rb registers install hook with network/shell execution"
        author       = "wtfpkg-rules"
        id           = "45288241-062b-44c7-b162-472d576e7a9f"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/gem-install-hooks.md"
        score        = 75
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1546, GEM, RUBY, PERSISTENCE"

    strings:
        $hook_post      = "Gem.post_install" ascii
        $hook_pre       = "Gem.pre_install" ascii
        $hook_post_u    = "Gem.post_uninstall" ascii

        $rb_system      = "system(" ascii
        // Tightened: require a known attack tool after the backtick so YARA can
        // extract a useful fixed atom (e.g. "`curl") instead of a single backtick.
        $rb_backtick    = /`(curl|wget|nc|bash|python|ruby|sh)\b[^`]+`/ ascii
        $rb_exec        = "exec(" ascii
        $rb_open        = "IO.popen(" ascii
        $rb_spawn       = "spawn(" ascii

        $rb_net_http    = "Net::HTTP" ascii
        $rb_uri         = "URI.open(" ascii
        $rb_open_uri    = "open-uri" ascii
        $rb_require_net = "require 'net/http'" ascii
        $rb_require_open= "require 'open-uri'" ascii

    condition:
        1 of ($hook_post, $hook_pre, $hook_post_u) and
        (
            1 of ($rb_system, $rb_backtick, $rb_exec, $rb_open, $rb_spawn) or
            1 of ($rb_net_http, $rb_uri, $rb_open_uri, $rb_require_net, $rb_require_open)
        )
}


rule wtfpkg_gem_native_ext_suspicious_exec
{
    meta:
        description  = "extconf.rb or Rakefile extension script contains shell execution with network patterns"
        author       = "wtfpkg-rules"
        id           = "2301ebc8-6df8-48bf-b56a-edbc8015cf91"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/gem-native-extension.md"
        score        = 75
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, T1059_004, GEM, RUBY"

    strings:
        $extconf_ctx    = "create_makefile(" ascii
        $extconf_ctx2   = "find_header(" ascii
        $extconf_ctx3   = "find_library(" ascii

        $rake_task      = "task :" ascii
        $rake_default   = "task default:" ascii

        // BUGFIX: was `"system.*curl"` / `"system.*wget"` (literal string, never matched).
        // Now proper YARA regexes matching system() calls that include curl/wget as arguments.
        $sys_curl       = /system\([^)]*curl/ ascii
        $sys_wget       = /system\([^)]*wget/ ascii
        $backtick_curl  = /`curl [^`]+`/ ascii
        $backtick_wget  = /`wget [^`]+`/ ascii
        $sys_bash       = "system('bash'" ascii
        $sys_sh         = "system('sh'" ascii
        $net_url        = /https?:\/\/[a-zA-Z0-9.\-]{4,}/ ascii

    condition:
        (1 of ($extconf_ctx, $extconf_ctx2, $extconf_ctx3) or
         1 of ($rake_task, $rake_default)) and
        (1 of ($sys_curl, $sys_wget, $backtick_curl, $backtick_wget, $sys_bash, $sys_sh)) and
        $net_url
}


rule wtfpkg_gem_gemspec_rakefile_extension
{
    meta:
        description  = "gemspec extensions field references Rakefile — higher-risk extension mechanism"
        author       = "wtfpkg-rules"
        id           = "6451cdfc-c8ed-44b3-b610-c61c98340ab1"
        date         = "2026-05-31"
        modified     = "2026-05-31"
        reference    = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/gem-build-script.md"
        score        = 65
        quality      = 75
        tags         = "SUPPLY_CHAIN, T1195_001, GEM, RUBY"

    strings:
        $gemspec_spec   = "Gem::Specification.new" ascii
        $gemspec_ext    = "spec.extensions" ascii
        $gemspec_ext2   = "s.extensions" ascii

        $rake_ref       = "'Rakefile'" ascii
        $rake_ref2      = "\"Rakefile\"" ascii
        $rake_ext       = "'ext/Rakefile'" ascii
        $rake_ext2      = "\"ext/Rakefile\"" ascii

    condition:
        $gemspec_spec and
        1 of ($gemspec_ext, $gemspec_ext2) and
        1 of ($rake_ref, $rake_ref2, $rake_ext, $rake_ext2)
}

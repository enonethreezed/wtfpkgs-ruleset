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
 */

/*
 * Detects rubygems_plugin.rb files that register post_install or pre_install
 * hooks containing network or shell execution payloads.
 * The combination of the Gem.post_install registration AND a shell/network
 * call is the key signal — normal plugins register hooks for UI callbacks,
 * not for running curl.
 */
rule wtfpkg_gem_plugin_install_hook_exec
{
    meta:
        description     = "rubygems_plugin.rb registers install hook with network/shell execution"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/gem-install-hooks.md"
        technique       = "GEM-02"
        severity        = "high"
        mitre_attack    = "T1195.001, T1546"

    strings:
        // Install hook registration
        $hook_post      = "Gem.post_install" ascii
        $hook_pre       = "Gem.pre_install" ascii
        $hook_post_u    = "Gem.post_uninstall" ascii

        // Shell execution in Ruby
        $rb_system      = "system(" ascii
        $rb_backtick    = /`[^`]{5,100}`/ ascii
        $rb_exec        = "exec(" ascii
        $rb_open        = "IO.popen(" ascii
        $rb_spawn       = "spawn(" ascii

        // Network access
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


/*
 * Detects extconf.rb or Rakefile extension scripts that include system command
 * execution beyond what is needed to generate a Makefile.
 * Legitimate extconf.rb calls create_makefile() and check for headers;
 * they should not invoke curl, wget, or shell commands with network URLs.
 */
rule wtfpkg_gem_native_ext_suspicious_exec
{
    meta:
        description     = "extconf.rb or Rakefile extension script contains shell execution with network patterns"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/gem-native-extension.md"
        technique       = "GEM-03"
        severity        = "high"
        mitre_attack    = "T1195.001, T1059.004"

    strings:
        // extconf.rb context
        $extconf_ctx    = "create_makefile(" ascii
        $extconf_ctx2   = "find_header(" ascii
        $extconf_ctx3   = "find_library(" ascii

        // Rakefile context
        $rake_task      = "task :" ascii
        $rake_default   = "task default:" ascii

        // Shell/network execution
        $sys_curl       = "system.*curl" ascii
        $sys_wget       = "system.*wget" ascii
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


/*
 * Detects .gemspec files where the extensions field points to a Rakefile
 * (not the standard extconf.rb) AND the Rakefile companion contains
 * suspicious execution. Applied to .gemspec files.
 * Also detects gemspec files with extensions pointing to unusual paths.
 */
rule wtfpkg_gem_gemspec_rakefile_extension
{
    meta:
        description     = "gemspec extensions field references Rakefile — higher-risk extension mechanism"
        author          = "wtfpkg-rules"
        date            = "2026-05-31"
        version         = "1.0"
        reference       = "https://github.com/0xv1n/WTFpkg/blob/main/content/techniques/gem-build-script.md"
        technique       = "GEM-01"
        severity        = "medium"
        mitre_attack    = "T1195.001"

    strings:
        // gemspec context
        $gemspec_spec   = "Gem::Specification.new" ascii
        $gemspec_ext    = "spec.extensions" ascii
        $gemspec_ext2   = "s.extensions" ascii

        // Rakefile (not extconf.rb) in extensions
        $rake_ref       = "'Rakefile'" ascii
        $rake_ref2      = "\"Rakefile\"" ascii
        $rake_ext       = "'ext/Rakefile'" ascii
        $rake_ext2      = "\"ext/Rakefile\"" ascii

    condition:
        $gemspec_spec and
        1 of ($gemspec_ext, $gemspec_ext2) and
        1 of ($rake_ref, $rake_ref2, $rake_ext, $rake_ext2)
}

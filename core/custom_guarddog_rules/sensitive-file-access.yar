rule sensitive_file_access
{
    meta:
        description = "Detects access to sensitive files and directories"
        author = "NPM Scanner Custom Rules"
        category = "file_access"
        
    strings:
        $ssh1 = "/.ssh/" nocase
        $ssh2 = ".ssh/id_" nocase
        $aws1 = "/.aws/" nocase
        $aws2 = ".aws/credentials" nocase
        $npm1 = ".npmrc" nocase
        $git1 = ".gitconfig" nocase
        $env1 = ".env" nocase
        $passwd = "/etc/passwd" nocase
        $shadow = "/etc/shadow" nocase
        
    condition:
        any of them
}

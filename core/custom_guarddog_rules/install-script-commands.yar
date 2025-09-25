rule install_script_commands
{
    meta:
        description = "Detects potentially malicious commands in install scripts"
        author = "NPM Scanner Custom Rules"
        category = "execution"
        
    strings:
        $curl = "curl" nocase
        $wget = "wget" nocase
        $chmod = "chmod +x" nocase
        $bash = "bash -c" nocase
        $sh = "sh -c" nocase
        $eval = "eval" nocase
        $download = "download" nocase
        
    condition:
        any of them
}

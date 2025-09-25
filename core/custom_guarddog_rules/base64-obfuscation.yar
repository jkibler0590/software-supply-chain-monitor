rule base64_obfuscation
{
    meta:
        description = "Detects potential base64 obfuscation"
        author = "NPM Scanner Custom Rules"
        category = "obfuscation"
        
    strings:
        $base64_1 = /[A-Za-z0-9+\/]{20,}={0,2}/
        $atob = "atob(" nocase
        $btoa = "btoa(" nocase
        $decode = "base64decode" nocase
        
    condition:
        any of them
}

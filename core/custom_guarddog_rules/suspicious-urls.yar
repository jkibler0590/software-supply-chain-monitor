rule suspicious_urls
{
    meta:
        description = "Detects suspicious URLs and domains"
        author = "NPM Scanner Custom Rules"
        category = "network"
        
    strings:
        $ip_pattern = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $suspicious_tld1 = ".tk" nocase
        $suspicious_tld2 = ".ml" nocase
        $suspicious_tld3 = ".ga" nocase
        $suspicious_domain1 = "bit.ly" nocase
        $suspicious_domain2 = "tinyurl" nocase
        $pastebin = "pastebin.com" nocase
        
    condition:
        any of them
}

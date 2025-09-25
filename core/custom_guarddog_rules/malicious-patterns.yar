rule cryptocurrency_keywords
{
    meta:
        description = "Detects cryptocurrency-related keywords that could indicate mining malware"
        author = "NPM Scanner Custom Rules"
        category = "malware"
        
    strings:
        $bitcoin1 = "bitcoin" nocase
        $bitcoin2 = "btc" nocase
        $ethereum = "ethereum" nocase
        $crypto1 = "cryptocurrency" nocase
        $crypto2 = "crypto" nocase
        $mining1 = "mining" nocase
        $mining2 = "miner" nocase
        $wallet1 = "wallet" nocase
        $wallet2 = "address" nocase
        
    condition:
        any of them
}

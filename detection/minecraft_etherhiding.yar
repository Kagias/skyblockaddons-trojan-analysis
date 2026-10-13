rule Minecraft_Fabric_EtherHiding_Stealer_Loader
{
    meta:
        description     = "Trojanized Fabric mod: Fabric Mixin bootstrap -> reflective Minecraft credential stealer -> Ethereum smart-contract (EtherHiding) dead-drop C2 resolver -> in-memory stage-2 JAR via DoH"
        author          = "opencode static analysis"
        date            = "2026-10-13"
        reference       = "systemnotifier[.]st ; contract 0x9044f5762e43b23ba91d124b51a045f1b51da652 ; Weedhack/Majanito family"
        sample_sha256   = "85ccb86cf78c138c55eda930a3d577f7d5891f65f51dfa785acc3d1a1f7b5efa"
        tlp             = "CLEAR"

    strings:
        // Ethereum RPC eth_call function selector = keccak256("text()")[:4]  (plaintext in the resolver class)
        $eth_selector   = "0x1f1bd692" ascii

        // DNS-over-HTTPS resolver hard-coded strings (C2 hostname resolution)
        $doh_path       = "/dns-query?name=" ascii
        $doh_type       = "&type=A" ascii

        // Fabric Mixin used as the execution bootstrap into net.minecraft.client.Minecraft.run
        $mixin_json     = "ece3700569f8.mixins.json" ascii
        $mixin_class    = "Mece3700569f8" ascii

        // Sample-specific randomly-named packages (high-confidence family/loader marker)
        $pkg_loader     = "q56p0dnpq/qw1mnsk/dq5m8eecjo/cxo7lzvo" ascii
        $pkg_decoy      = "y0whhmrf/t52qmy3n/jyvfg75jyq/edmst" ascii

        // Credential access against the Minecraft session object
        $cred_token     = "getAccessToken" ascii
        $cred_profile   = "getProfileId" ascii
        $cred_name      = "getUser" ascii

        // Fabric entrypoint / reflective launcher method
        $fabric_init    = "net/fabricmc/api/ModInitializer" ascii
        $launch_method  = "onInitialize" ascii

        // Decoy "protection" layer artifacts (VM + vault + integrity manifest)
        $decoy_vault    = "vault.bin" ascii
        $decoy_integr    = "integrity.bin" ascii

    condition:
        // Target individual .class files (scan extracted files, not the compressed JAR)
        (
            ($eth_selector and $doh_path and $doh_type)
            or
            ($pkg_loader and $pkg_decoy)
            or
            ($mixin_json and $mixin_class and ($cred_token or $cred_profile))
            or
            ($pkg_loader and $cred_token and $cred_profile and $cred_name and $launch_method)
            or
            ($fabric_init and $cred_token and $cred_profile and $decoy_vault and $decoy_integr)
        )
}

rule Minecraft_Fabric_Mixin_Class_Bootstrap
{
    meta:
        description = "Single malicious Fabric Mixin class that reflectively launches a randomly-named loader from Minecraft.run (HEAD inject)"
        author      = "opencode static analysis"
        date        = "2026-10-13"

    strings:
        $pkg = "mece3700569f8" ascii
        $minecraft = "net/minecraft/client/Minecraft" ascii
        $init = "onInitialize" ascii
        $forname = "java/lang/Class" ascii
        $reflect = "java/lang/reflect/Method" ascii
        $inject = "org/spongepowered/asm/mixin/injection/Inject" ascii

    condition:
        uint32be(0) == 0xCAFEBABE and all of them
}

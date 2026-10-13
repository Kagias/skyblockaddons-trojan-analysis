# A Fake "SkyBlockAddons" Mod That Steals Your Minecraft Account — and Hides Its Server on the Blockchain

[![YARA](https://img.shields.io/badge/detection-YARA-informational)](detection/minecraft_etherhiding.yar)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](LICENSE)
![Analysis](https://img.shields.io/badge/analysis-static%20only-blue)

*An analysis of `SkyblockAddons-26.2.jar`: a trojanized Fabric mod that steals Minecraft
login tokens and fetches its next stage from an Ethereum smart contract.*

> **Sample:** `SkyblockAddons-26.2.jar` · SHA-256
> `85ccb86cf78c138c55eda930a3d577f7d5891f65f51dfa785acc3d1a1f7b5efa`
> **Family:** EtherHiding / Weedhack–Majanito style infostealer
> **Analysis:** static only — the sample was never executed.

📄 **In this repo**
- [Full technical writeup](reports/technical-analysis.md) (decompiled evidence, execution chain, ATT&CK mapping, repro steps)
- [YARA rule](detection/minecraft_etherhiding.yar)
- [Machine-readable IOCs](iocs/iocs.csv) · [JSON](iocs/iocs.json)
- [Analysis scripts](scripts/) (string deobfuscator, integrity manifest verifier)

## Quick IOCs

| Type | Value |
|---|---|
| C2 domain | `systemnotifier[.]st` |
| Stage-2 URL | `https://systemnotifier.st/api/static/loading` |
| ETH contract (dead-drop) | `0x9044f5762e43b23ba91d124b51a045f1b51da652` |
| eth_call selector | `0x1f1bd692` (`keccak256("text()")[:4]`) |
| ETH creator | `0x34d7fb0cdD43F39DdbDbe85cD6e0688B7596e665` |
| Sample SHA-256 | `85ccb86cf78c138c55eda930a3d577f7d5891f65f51dfa785acc3d1a1f7b5efa` |

> ⚠️ Defensive/educational analysis. Not affiliated with the legitimate mod authors.
> The malware sample is **not** distributed in this repository.

---

Minecraft mods are a perfect malware delivery vehicle. They run with full desktop
privileges, players download them constantly from Discord, YouTube descriptions and shady
mirrors, and the "install this and get cool features" social contract means almost nobody
inspects the JAR. This sample weaponizes all of that.

The file is called **`SkyblockAddons-26.2.jar`** — a name that borrows the reputation of the
enormously popular SkyBlockAddons mod. But open it up, and it isn't SkyBlockAddons at all.

---

## What it really is

Inside `fabric.mod.json` the mod introduces itself honestly:

> **Toggle Sprint Display** by *Aeltumn* — a tiny Fabric mod that shows a HUD indicator for
> whether you're sprinting.

The author of that mod is innocent. The attacker took Aeltumn's legitimate mod and repackaged
it with one extra piece: a second mixin registration pointing at a randomly-named package:

```json
"mixins": [
    "toggle-sprint-display.mixins.json",
    "ece3700569f8.mixins.json"        <-- added by the attacker
]
```

Fabric Mixins let a mod inject code straight into the base game. This one hooks the very
first line of `Minecraft.run()` — the main game loop — so it executes before you even reach
the title screen. From there it reflectively launches the real payload, which lives in a
package named `q56p0dnpq.qw1mnsk.dq5m8eecjo.cxo7lzvo`.

---

## 1. It steals your Minecraft session

The first thing the payload does is read your logged-in Minecraft account:

```java
User user = Minecraft.getInstance().getUser();
creds.addProperty("username",    user.getName());
creds.addProperty("uuid",        user.getProfileId().toString());
creds.addProperty("accessToken", user.getAccessToken());   // <-- the prize
```

That `accessToken` is a live Microsoft/Xbox session bearer token. It is enough to **take over
the account without a password** — and stolen Minecraft accounts are a thriving grey market
(usernames, rare capes, in-game items, and resale to griefers and scammers). No legitimate
"HUD sprint indicator" has any business calling `getAccessToken()`.

---

## 2. It hides its command-and-control server on the blockchain

Here's the genuinely clever part. Hardcoding a C2 domain is a single point of failure —
security vendors block it, the host takes it down, game over. So this sample doesn't store
its server anywhere. It *asks the Ethereum blockchain*.

The malware:

1. Hardcodes the address of an **Ethereum smart contract**:
   `0x9044f5762e43b23ba91d124b51a045f1b51da652`.
2. Calls the contract's `text()` function (`eth_call`, function selector `0x1f1bd692`) —
   trying **31 different public Ethereum RPC endpoints** until one answers.
3. Decodes the returned string, which is literally the C2 domain:

   > **`systemnotifier.st`**

This trick is called **EtherHiding**. The domain lives in a public, immutable, censorship-
resistant blockchain. The operator can point it at a new server any time by updating the
contract, without ever changing the malware file. Nobody can "seize" the lookup, and there's
no registrar or hosting provider to pressure. (You can verify it yourself with a single
public RPC call — the contract is unverified and still live.)

---

## 3. It downloads stage two — straight into memory

Once it knows where to go, it builds the URL
`https://systemnotifier.st/api/static/loading` and pulls down a second JAR.

Two evasions stand out:

* **It resolves the domain over DNS-over-HTTPS** (hardcoded `1.1.1.1` and `8.8.8.8`,
  querying `/dns-query`), then opens a TLS socket to the resolved IP with the correct SNI.
  This sails straight past `hosts`-file blocks and DNS sinkholes — the kind of thing a
  savvy player might set up after being burned before.
* **The second-stage JAR never touches the disk.** It is parsed in memory, its classes
  loaded by a custom `ClassLoader` (`defineClass` on raw bytes) and its resources served by
  a custom in-memory `URLHandler`. It then invokes `com.example.Main.initialize(...)` with
  your stolen credentials as JSON.

Result: almost nothing for a file scanner or a casual user to find — no dropped EXE, no
second `.jar` sitting in the mods folder.

---

## 4. The "serious malware" costume

Sprinkled throughout is a whole subsystem that *looks* like a professional Java protector: a
custom bytecode "**VM**", a "**Guard**" anti-tamper module, an `integrity.bin` manifest of
class hashes, and a 1.5 MB "**vault.bin**".

It's a decoy. The integrity hashes are internally valid but never used; the VM looks for a
`vm.bin` file that **doesn't exist**, so it can't even run; and `vault.bin` is 1.5 million
bytes of pure random noise (entropy 7.9999 — i.e. padding). It's there to make the sample
look daunting and to send analysts down dead ends. The actual attack is small, readable, and
doesn't depend on any of it.

---

## 5. What this is part of

The tooling, the Ethereum dead-drop, the in-memory second stage and the target all line up
with the documented **Weedhack** malware-as-a-service family and the broader "EtherHiding"
Minecraft-stealer scene that has been circulating in modding communities. In that ecosystem
the bolt-ons sold to buyers include session-cookie theft, crypto-wallet theft, and a remote
keylogger — which is what the second stage is most likely fetching here.

---

## Warning signs (for players)

* **The filename lies.** "SkyBlockAddons" has nothing to do with the mod inside
  ("Toggle Sprint Display"). If the filename and the mod identity don't match, walk away.
* **Download only from official sources.** CurseForge/Modrinth/official GitHub — not from a
  random Discord attachment, a Google Drive link, or a "mirror".
* **Brand-new or low-download accounts** posting "fixes" and "cracked/hacked clients" are a
  classic lure.
* **If you ran something like this, assume your session is compromised.** Log out of the
  launcher, change your Microsoft password, and revoke app sessions. Changing the password
  invalidates the stolen token.

## What defenders should watch for

* Fabric mods whose `mixins.json` references a **second, randomly-named package**.
* Outbound HTTPS to a **literal IP with a mismatched SNI**, preceded by `/dns-query`
  (DNS-over-HTTPS) traffic that bypasses managed DNS.
* **`eth_call` JSON-RPC** with `data = 0x1f1bd692` leaving a game or workstation — that is
  a `text()` read against a Solidity contract, a strong EtherHiding indicator.
* The C2 domain `systemnotifier[.]st` and the contract
  `0x9044f5762e43b23ba91d124b51a045f1b51da652`.

---

## The takeaway

Two ideas are doing all the heavy lifting here, and both will keep showing up:

1. **The blockchain as un-killable infrastructure.** A smart contract is a C2 you can't
   seize, block, or register-and-takedown. Expect to see much more of this.
2. **Repackaging as a trust bypass.** No new exploit, no zero-day — just taking a working
   mod, adding one line to its manifest, and letting reputation do the rest.

The sample is small, the credential theft is blatant, and the "protection" is theater. The
only thing sophisticated about it is where it keeps its phone number.

---

*Indicators, a YARA rule and full reverse-engineering notes accompany this writeup. Analysis
was performed statically; the sample was not executed. TLP:CLEAR.*

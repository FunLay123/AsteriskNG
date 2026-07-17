# FakeDNS Bypass-Exclusion Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Excluded apps (blacklist mode: listed apps; whitelist mode: unlisted apps) currently receive a synthetic FakeDNS IP (`198.18.0.0/15`) for every domain, because their DNS queries are resolved by the system resolver (`netd`), not by the app's own socket — so no UID-based match (`-m owner --uid-owner`, or the eBPF `bpf_get_socket_uid()` helper, which reads the same `sk_uid` field) can ever attribute that DNS packet back to the app. Their real TCP/UDP data connection, however, *is* opened by the app's own socket and *is* correctly excluded from the tunnel today — which means it dials the synthetic FakeDNS IP directly and fails, breaking the app entirely. This plan stops excluding connections whose destination falls inside the FakeDNS pool, routes them into a dedicated "bypass-direct" tunnel path instead, and makes Xray route that dedicated path to the `direct` (freedom) outbound — so the app's real connection still gets sniffed/re-resolved to its real destination and dialed directly, without ever traversing the actual VPN/proxy outbound.

**Architecture:** Add a second, parallel inbound + redirect target per root mode (tproxy TPROXY port, tun2socks tunnel port, bpf2socks bridge port), reachable only by app UIDs that are excluded from the main tunnel AND only for destinations inside the FakeDNS pool CIDR. Each new inbound is tagged distinctly in Xray and pinned to the `direct` outbound via a routing rule keyed on `inboundTag`, mirroring the existing `dns-out` hijack rule pattern. Everything else (excluded apps' non-FakeDNS-pool traffic, and all traffic for non-excluded apps) is untouched.

**Tech Stack:** Kotlin (Xray JSON config generation, root-mode iptables script generation), C (bpf2socks native eBPF connect-time policy + userspace bridge daemon), iptables/ip6tables, eBPF (`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`).

## Global Constraints

- The FakeDNS pool is IPv4-only: `198.18.0.0/15`, defined as `XrayFakeDnsIpv4Pool` in `app/src/main/kotlin/engine/xray/XrayFeatureDefaults.kt:19`. There is no IPv6 FakeDNS pool in this codebase — IPv6 tasks are out of scope.
- Excluded-app traffic must never reach `XrayTags.PROXY` (the remote VPN outbound). It must always resolve to `XrayTags.DIRECT` (freedom outbound, value `"direct"`, `app/src/main/kotlin/engine/xray/XrayConfigSupport.kt`).
- Do not change behavior for excluded apps' traffic to destinations outside the FakeDNS pool — that already bypasses correctly via existing `-m owner --uid-owner` RETURN rules (`appendOutputApplicationBypassRules` in `TproxyIptablesScript.kt` / `Tun2SocksIptablesScript.kt`, and the existing `bypass_jumps` path in `bpf2socks/src/main/native/connect_prog.c`). Leave that path's logic untouched; only add a new, narrower carve-out ahead of it.
- Do not change behavior for non-excluded (proxied) apps at all.
- New ports must not collide with existing reserved ports: `DefaultTproxyPort = 65535`, `DefaultTun2SocksProxyPort = 65534`, `DefaultRootHttpProxyPort = 65533`, `RootBpf2SocksDefaultBridgePort = 65532` (all derived from `NetworkLimits.PORT_MAX = 65535` in `app/src/main/kotlin/engine/network/NetworkLimits.kt`).
- eBPF program changes (bpf2socks) are only verified by actually loading the program on-device and checking for BPF verifier errors — invalid `bpf_insn` sequences compile fine in Kotlin/C but fail (or silently misbehave) only at `bpf(BPF_PROG_LOAD, ...)` time. Every bpf2socks task's manual verification step must include a real on-device load check, not just `./gradlew build`.
- Follow existing code patterns exactly — this file has three near-identical iptables script variants (tproxy, tun2socks) and one native eBPF policy engine (bpf2socks); do not introduce a fourth, different way of doing the same thing.

---

### Task 1: Port constants and Xray tags for the bypass-direct path

**Files:**
- Modify: `app/src/main/kotlin/engine/tproxy/TproxyConstants.kt`
- Modify: `app/src/main/kotlin/engine/tun2socks/Tun2SocksConstants.kt`
- Modify: `app/src/main/kotlin/engine/root/RootConstants.kt`
- Modify: `app/src/main/kotlin/engine/xray/XrayConfigSupport.kt`

**Interfaces:**
- Produces: `RootTproxyBypassPort`, `RootTun2SocksBypassPort`, `RootBpf2SocksBypassBridgePort`, `RootBpf2SocksBypassSocksPort` (all `Int`); `XrayTags.TPROXY_BYPASS_INBOUND`, `XrayTags.TUN2SOCKS_BYPASS_INBOUND`, `XrayTags.BPF2SOCKS_BYPASS_INBOUND` (all `String`). Later tasks consume these exact names.

- [ ] **Step 1:** In `app/src/main/kotlin/engine/tproxy/TproxyConstants.kt`, next to the existing `const val DefaultTproxyPort = NetworkLimits.PORT_MAX` (line 10), add:
  ```kotlin
  const val RootTproxyBypassPort = NetworkLimits.PORT_MAX - 4
  ```
- [ ] **Step 2:** In `app/src/main/kotlin/engine/tun2socks/Tun2SocksConstants.kt`, next to `const val DefaultTun2SocksProxyPort = 65534` (line 9), add:
  ```kotlin
  const val RootTun2SocksBypassPort = 65530
  ```
- [ ] **Step 3:** In `app/src/main/kotlin/engine/root/RootConstants.kt`, next to `const val RootBpf2SocksDefaultBridgePort = NetworkLimits.PORT_MAX - 3` (line 37), add:
  ```kotlin
  const val RootBpf2SocksBypassBridgePort = NetworkLimits.PORT_MAX - 6
  const val RootBpf2SocksBypassSocksPort = NetworkLimits.PORT_MAX - 7
  ```
- [ ] **Step 4:** In `app/src/main/kotlin/engine/xray/XrayConfigSupport.kt`, inside `internal object XrayTags`, next to `const val TPROXY_INBOUND = "tproxy-in"`, add the three new tags:
  ```kotlin
  const val TPROXY_BYPASS_INBOUND = "tproxy-bypass-in"
  const val TUN2SOCKS_BYPASS_INBOUND = "tun2socks-bypass-in"
  const val BPF2SOCKS_BYPASS_INBOUND = "bpf2socks-bypass-in"
  ```
- [ ] **Step 5:** Build the module to confirm it compiles: `./gradlew :app:compileDebugKotlin`. Expected: BUILD SUCCESSFUL.
- [ ] **Step 6: Commit**
  ```bash
  git add app/src/main/kotlin/engine/tproxy/TproxyConstants.kt app/src/main/kotlin/engine/tun2socks/Tun2SocksConstants.kt app/src/main/kotlin/engine/root/RootConstants.kt app/src/main/kotlin/engine/xray/XrayConfigSupport.kt
  git commit -m "feat: add ports and xray tags for fakedns-pool bypass-direct path"
  ```

---

### Task 2: Shared Xray inbound + routing-rule builders for the bypass-direct path

**Files:**
- Modify: `app/src/main/kotlin/engine/root/RootConfigSupport.kt`
- Modify: `app/src/main/kotlin/engine/xray/XrayRoutingConfig.kt`

**Interfaces:**
- Consumes: `XrayTags.DIRECT`, `XrayProtocols.TUNNEL` (existing, used identically to `buildTproxyTunnelInbound` in `TproxyConfig.kt:81-119`).
- Produces: `fun buildRootBypassDirectInbound(tag: String, port: Int): JsonObject` (in `RootConfigSupport.kt`), `fun buildXrayBypassDirectRule(inboundTags: List<String>): JsonObject?` (in `XrayRoutingConfig.kt`). Tasks 4, 5, and 8 call these by these exact names.

- [ ] **Step 1:** In `app/src/main/kotlin/engine/root/RootConfigSupport.kt`, add a new function that builds a TPROXY-style tunnel inbound identical in shape to `buildTproxyTunnelInbound` (`TproxyConfig.kt:81-119`) but generic over tag/port, with sniffing always enabled (this inbound only ever carries traffic that must be re-resolved by sniffing, since the client already holds a fake IP) and `routeOnly` left `false` so Xray substitutes the sniffed domain's real IP rather than keeping the FakeDNS-pool address:
  ```kotlin
  internal fun buildRootBypassDirectInbound(tag: String, port: Int): JsonObject {
      return buildJsonObject {
          put("tag", tag)
          put("port", port)
          put("protocol", XrayProtocols.TUNNEL)
          put(
              "settings",
              buildJsonObject {
                  put("allowedNetwork", "tcp,udp")
                  put("followRedirect", true)
                  put("userLevel", 0)
              },
          )
          put(
              "streamSettings",
              buildJsonObject {
                  put(
                      "sockopt",
                      buildJsonObject {
                          put("tproxy", "tproxy")
                      },
                  )
              },
          )
          put(
              "sniffing",
              buildJsonObject {
                  put("enabled", true)
                  put("destOverride", listOf("http", "tls", "quic").toJsonStringArray())
                  put("routeOnly", false)
              },
          )
      }
  }
  ```
  Add the necessary imports (`engine.xray.XrayProtocols`, `engine.xray.toJsonStringArray`, `kotlinx.serialization.json.JsonObject`, `kotlinx.serialization.json.buildJsonObject`, `kotlinx.serialization.json.put`) if not already present in the file — check the file's current import block first with `Read` before editing.
- [ ] **Step 2:** In `app/src/main/kotlin/engine/xray/XrayRoutingConfig.kt`, add a routing-rule builder mirroring `buildXrayDnsHijackRule` (lines 103-112) exactly, but targeting `XrayTags.DIRECT` instead of `XrayTags.DNS_OUT`:
  ```kotlin
  internal fun buildXrayBypassDirectRule(inboundTags: List<String>): JsonObject? {
      val tags = inboundTags.toTrimmedNonEmptyDistinctList()
      if (tags.isEmpty()) return null
      return buildJsonObject {
          put("inboundTag", tags.toJsonStringArray())
          put("outboundTag", XrayTags.DIRECT)
      }
  }
  ```
- [ ] **Step 3:** In the same file, wire the new rule into `routingRules` (lines 61-86) with priority equal to the DNS hijack rule — insert it right after the existing `if (effectiveLocalDnsEnabled) { buildXrayDnsHijackRule(...) }` block (line 72-74) and before the `if (routeDirectDns)` block (line 75), so it is evaluated before any domain/geosite rule that could otherwise send this inbound's traffic through the proxy outbound:
  ```kotlin
  buildXrayBypassDirectRule(bypassDirectInboundTags)?.let(::add)
  ```
  This requires adding a new parameter `bypassDirectInboundTags: List<String>` to `AppState.routingRules(...)` (line 61-67) and to the public `buildXrayRoutingPlan(...)` (line 24-30) that calls it, threading it through the same way `dnsHijackInboundTags` is already threaded. Update the single call site inside `buildXrayRoutingPlan` at line 35-41 to pass it through.
- [ ] **Step 4:** Build to confirm compilation: `./gradlew :app:compileDebugKotlin`. Expected: BUILD SUCCESSFUL (note: call sites of `buildXrayRoutingPlan` in `TproxyConfig.kt`, `Tun2SocksConfig.kt`, `Bpf2SocksConfig.kt` will now fail to compile until Tasks 4/5/8 update them — if this task is reviewed standalone, temporarily default the new parameter to `emptyList()` in `buildXrayRoutingPlan`'s signature so existing call sites keep compiling, and remove the default in Task 4 once real values are threaded through).
- [ ] **Step 5: Commit**
  ```bash
  git add app/src/main/kotlin/engine/root/RootConfigSupport.kt app/src/main/kotlin/engine/xray/XrayRoutingConfig.kt
  git commit -m "feat: add shared bypass-direct xray inbound and routing-rule builders"
  ```

---

### Task 3: Root shell-script helper for CIDR-scoped bypass redirect (tproxy + tun2socks share this)

**Files:**
- Modify: `app/src/main/kotlin/engine/root/RootShellScript.kt`

**Interfaces:**
- Consumes: `RootIptablesConfig.proxyAppListMode`, `.proxyApplicationUids`, `.forcedBypassUids` (existing fields, same ones `appendOutputDnsBypassNatRules` already consumes at `RootShellScript.kt:23-57`).
- Produces: `fun StringBuilder.appendOutputFakednsPoolBypassRedirectRules(command: String, chain: String, mode: Int, forcedBypassUids: List<Int>, uids: List<Int>, whitelistSystemUids: List<Int>, fakednsPoolCidr: String, bypassPort: Int, onIp: String, mark: String)`. Tasks 4 and 5 call this by this exact name.

- [ ] **Step 1:** In `app/src/main/kotlin/engine/root/RootShellScript.kt`, add this function directly below `appendOutputDnsBypassNatRules` (which ends at line 57), following the exact same per-uid-vs-negated-owner pattern that function already uses, but redirecting into the tunnel (`TPROXY`) instead of DNAT-ing out of it:
  ```kotlin
  /**
   * For excluded UIDs, redirects (rather than bypasses) connections whose destination falls
   * inside the FakeDNS pool CIDR. A bypassed app's own DNS never reaches this pool correctly
   * attributed (netd resolves DNS under its own uid, not the app's — see
   * appendOutputDnsBypassNatRules's doc comment) so the app is handed a synthetic FakeDNS IP
   * regardless of exclusion. Its real data connection, opened by the app's own socket, IS
   * correctly attributable — so instead of letting that connection dial the synthetic IP
   * directly (which always fails), this sends it into a dedicated tunnel inbound that sniffs
   * the real domain and redials it, then routes straight to the direct/freedom outbound.
   */
  internal fun StringBuilder.appendOutputFakednsPoolBypassRedirectRules(
      command: String,
      chain: String,
      mode: Int,
      forcedBypassUids: List<Int>,
      uids: List<Int>,
      whitelistSystemUids: List<Int>,
      fakednsPoolCidr: String,
      bypassPort: Int,
      onIp: String,
      mark: String,
  ) {
      fun appendRedirectForUid(uid: Int) {
          appendScript(
              """
              $command -t mangle -A $chain -d ${fakednsPoolCidr.shellQuote()} -m owner --uid-owner $uid -p tcp -j TPROXY --on-port $bypassPort --on-ip $onIp --tproxy-mark $mark
              $command -t mangle -A $chain -d ${fakednsPoolCidr.shellQuote()} -m owner --uid-owner $uid -p udp -j TPROXY --on-port $bypassPort --on-ip $onIp --tproxy-mark $mark
              """,
          )
      }
      forcedBypassUids.distinct().forEach(::appendRedirectForUid)
      when (mode) {
          ProxyAppListModeBlacklist -> uids.distinct().forEach(::appendRedirectForUid)
          ProxyAppListModeWhitelist -> {
              val allowed = (uids.distinct() + whitelistSystemUids).distinct()
              if (allowed.isNotEmpty()) {
                  val negatedOwners = allowed.joinToString(" ") { uid -> "-m owner ! --uid-owner $uid" }
                  appendScript(
                      """
                      $command -t mangle -A $chain -d ${fakednsPoolCidr.shellQuote()} $negatedOwners -p tcp -j TPROXY --on-port $bypassPort --on-ip $onIp --tproxy-mark $mark
                      $command -t mangle -A $chain -d ${fakednsPoolCidr.shellQuote()} $negatedOwners -p udp -j TPROXY --on-port $bypassPort --on-ip $onIp --tproxy-mark $mark
                      """,
                  )
              }
          }
          else -> Unit
      }
  }
  ```
  This reuses `ProxyAppListModeBlacklist`/`ProxyAppListModeWhitelist` and `shellQuote()`, already imported in this file (verify with `Read` before editing — `appendOutputDnsBypassNatRules` in the same file already imports both).
- [ ] **Step 2:** Also add the matching cleanup delete-loop helper, following the exact pattern of `appendDeleteRuleLoop` calls used elsewhere for other per-uid rule sets (see `TproxyIptablesScript.kt`'s `appendIptablesVariantCleanupRules`, lines 274-306, for the pattern of looping delete over every possible uid). Add:
  ```kotlin
  internal fun StringBuilder.appendOutputFakednsPoolBypassRedirectCleanupRules(
      command: String,
      chain: String,
      forcedBypassUids: List<Int>,
      uids: List<Int>,
      whitelistSystemUids: List<Int>,
      fakednsPoolCidr: String,
  ) {
      (forcedBypassUids + uids + whitelistSystemUids).distinct().forEach { uid ->
          appendDeleteRuleLoop(command, chain, "-d ${fakednsPoolCidr.shellQuote()} -m owner --uid-owner $uid -p tcp -j TPROXY")
          appendDeleteRuleLoop(command, chain, "-d ${fakednsPoolCidr.shellQuote()} -m owner --uid-owner $uid -p udp -j TPROXY")
      }
  }
  ```
- [ ] **Step 3:** Build: `./gradlew :app:compileDebugKotlin`. Expected: BUILD SUCCESSFUL.
- [ ] **Step 4: Commit**
  ```bash
  git add app/src/main/kotlin/engine/root/RootShellScript.kt
  git commit -m "feat: add fakedns-pool bypass redirect iptables rule builder"
  ```

---

### Task 4: Wire the bypass-direct path into tproxy mode

**Files:**
- Modify: `app/src/main/kotlin/engine/tproxy/TproxyConfig.kt`
- Modify: `app/src/main/kotlin/engine/tproxy/TproxyIptablesScript.kt`

**Interfaces:**
- Consumes: `buildRootBypassDirectInbound`, `buildXrayBypassDirectRule` (Task 2), `appendOutputFakednsPoolBypassRedirectRules`, `appendOutputFakednsPoolBypassRedirectCleanupRules` (Task 3), `RootTproxyBypassPort`, `XrayTags.TPROXY_BYPASS_INBOUND` (Task 1), `XrayFakeDnsIpv4Pool` (existing, `XrayFeatureDefaults.kt:19`).

- [ ] **Step 1:** In `TproxyConfig.kt`, add the bypass inbound to `buildTproxyInbounds` (lines 66-79):
  ```kotlin
  add(buildRootBypassDirectInbound(XrayTags.TPROXY_BYPASS_INBOUND, RootTproxyBypassPort))
  ```
  placed after the existing `add(buildTproxyTunnelInbound(...))` line.
- [ ] **Step 2:** In `buildTproxyStartConfig` (lines 44-64), the `buildRootStartConfig` call currently passes `dnsHijackInboundTags = listOf(XrayTags.TPROXY_INBOUND)` (line 50). Once Task 2 threads a `bypassDirectInboundTags` parameter through `buildXrayRoutingPlan`, find wherever `buildRootStartConfig` forwards to it (`Read` `RootConfigSupport.kt`'s `buildRootStartConfig` to find the exact call) and pass `bypassDirectInboundTags = listOf(XrayTags.TPROXY_BYPASS_INBOUND)` alongside the existing `dnsHijackInboundTags` argument.
- [ ] **Step 3:** In `TproxyIptablesScript.kt`, inside the block that already calls `appendOutputUidReturnRules(variant.command, variant.outputChain, config.forcedBypassUids)` followed by `appendOutputApplicationBypassRules(...)` (this appears twice: lines 132-138 inside the `enableEbpfRules` branch, and again wherever the non-eBPF path performs the equivalent — locate both call sites with `Read` before editing), insert a call to the new helper **immediately before** each `appendOutputUidReturnRules` call, so the CIDR-scoped redirect is evaluated before the general RETURN rule can short-circuit the chain:
  ```kotlin
  appendOutputFakednsPoolBypassRedirectRules(
      command = variant.command,
      chain = variant.outputChain,
      mode = config.proxyAppListMode,
      forcedBypassUids = config.forcedBypassUids,
      uids = config.proxyApplicationUids,
      whitelistSystemUids = RootProxyAppWhitelistSystemUids,
      fakednsPoolCidr = XrayFakeDnsIpv4Pool,
      bypassPort = RootTproxyBypassPort,
      onIp = variant.tproxyOnIp,
      mark = config.mark,
  )
  ```
  Skip this insertion for the `variant.tproxyOnIp == "::"` (IPv6) variant — per Global Constraints, the FakeDNS pool is IPv4-only, so only call this for the IPv4 `TproxyIptablesVariant` (check how the two variants are distinguished — `TproxyIptablesScript.kt` iterates `variant.tproxyOnIp`; guard the new call with `if (variant.tproxyOnIp != "::")`).
- [ ] **Step 4:** In `appendIptablesVariantCleanupRules` (`TproxyIptablesScript.kt:274-306`), add the matching cleanup call (also IPv4-only-guarded) using `appendOutputFakednsPoolBypassRedirectCleanupRules` with the same arguments (minus `onIp`/`bypassPort`/`mark`, matching Task 3's cleanup signature).
- [ ] **Step 5:** Build: `./gradlew :app:compileDebugKotlin`. Expected: BUILD SUCCESSFUL.
- [ ] **Step 6: Manual verification** (requires a rooted test device with tproxy mode active and a blacklist-excluded app installed):
  1. Install and start VPN in tproxy mode with the test app blacklisted.
  2. `su -c "iptables -t mangle -L <outputChain> -v -n" ` (substitute the actual chain name from `TproxyOutputChain` in `TproxyConstants.kt`) — confirm the new `-d 198.18.0.0/15 ... -j TPROXY --on-port 65531` rule appears **before** the plain RETURN rule for the same uid.
  3. Open the excluded app, trigger network activity, and confirm via `adb logcat -s asteriskng` (or the xray core log path) that its domains now show `app/dispatcher: default route ... via` a **direct** outbound rather than remaining stuck on the FakeDNS IP with no follow-up connection — cross-check the same domain no longer times out from the app's perspective.
- [ ] **Step 7: Commit**
  ```bash
  git add app/src/main/kotlin/engine/tproxy/TproxyConfig.kt app/src/main/kotlin/engine/tproxy/TproxyIptablesScript.kt
  git commit -m "feat: route excluded apps' fakedns-pool connections to direct outbound (tproxy)"
  ```

---

### Task 5: Wire the bypass-direct path into tun2socks mode

**Files:**
- Modify: `app/src/main/kotlin/engine/tun2socks/Tun2SocksConfig.kt`
- Modify: `app/src/main/kotlin/engine/tun2socks/Tun2SocksIptablesScript.kt`

**Interfaces:**
- Consumes: same Task 2/3 builders as Task 4, plus `RootTun2SocksBypassPort`, `XrayTags.TUN2SOCKS_BYPASS_INBOUND` (Task 1).

- [ ] **Step 1:** Mirror Task 4 Step 1 exactly, in `Tun2SocksConfig.kt`'s `buildTun2SocksInbounds` (lines 99-112), adding `add(buildRootBypassDirectInbound(XrayTags.TUN2SOCKS_BYPASS_INBOUND, RootTun2SocksBypassPort))`.
- [ ] **Step 2:** Mirror Task 4 Step 2: thread `bypassDirectInboundTags = listOf(XrayTags.TUN2SOCKS_BYPASS_INBOUND)` through wherever `Tun2SocksConfig.kt` calls `buildRootStartConfig` (the existing `dnsHijackInboundTags = listOf(XrayTags.TUN2SOCKS_INBOUND)` call site, near line 65 per the earlier grep of this file).
- [ ] **Step 3:** In `Tun2SocksIptablesScript.kt`, tun2socks does not use `TPROXY` — it routes captured OUTPUT traffic to the `asterisk0` tun device via the fwmark + `ip rule`/`ip route` mechanism already used for its normal marked traffic (see the existing `appendOutputApplicationMarkRules`/`appendUdpDnsMarkRule` calls in this file, and `appendScript("${variant.command} -t mangle -A ${variant.outputChain} -o 'asterisk0' -j RETURN")` at line 142, which is how the tun device's *own* outbound traffic avoids re-capture). Because tun2socks marks packets with `config.mark` and lets the kernel's `ip rule`/`ip route` for that mark push them out through `asterisk0` (not TPROXY's on-port redirect), the "second target port" here is not a kernel redirect target — it is simply the **destination port tun2socks's userspace relay listens on inside the tunnel**. Read `Tun2SocksRootRunner.kt` (or wherever the tun2socks userspace process's own listen port is configured — grep for `socks5ProxyPort`/`Tun2SocksConfig` usage) to confirm how a marked packet maps to which local port Xray receives it on, then add the CIDR-scoped redirect using the **same mark** (`config.mark`) but writing the destination rewrite as a `DNAT` in the `nat` table (not `TPROXY`) to `127.0.0.1:<RootTun2SocksBypassPort>`, positioned in the mangle `outputChain` before the existing `appendOutputApplicationBypassRules`-equivalent call in this file, analogous to Task 4 Step 3. Use `appendOutputFakednsPoolBypassRedirectRules` from Task 3, but confirm its `TPROXY` jump target is correct for this mode before using it verbatim — if tun2socks's existing traffic capture does not use `TPROXY` at all (verify by re-reading how `variant.outputChain`'s existing marked rules reach the tun device), adapt Task 3's helper with a tun2socks-specific variant that DNATs instead, following whichever pattern `appendPreroutingDnsTproxyRules`'s tun2socks sibling already uses for redirecting single ports.
- [ ] **Step 4:** Add the matching cleanup call in this file's `appendIptablesVariantCleanupRules` (lines 170-200), mirroring Task 4 Step 4.
- [ ] **Step 5:** Build: `./gradlew :app:compileDebugKotlin`. Expected: BUILD SUCCESSFUL.
- [ ] **Step 6: Manual verification** — same procedure as Task 4 Step 6, run against tun2socks mode instead of tproxy.
- [ ] **Step 7: Commit**
  ```bash
  git add app/src/main/kotlin/engine/tun2socks/Tun2SocksConfig.kt app/src/main/kotlin/engine/tun2socks/Tun2SocksIptablesScript.kt
  git commit -m "feat: route excluded apps' fakedns-pool connections to direct outbound (tun2socks)"
  ```

---

### Task 6: bpf2socks native — redirect excluded UIDs' FakeDNS-pool connections instead of bypassing them

**Files:**
- Modify: `bpf2socks/src/main/native/bpf2socks.h`
- Modify: `bpf2socks/src/main/native/connect_prog.c`

**Interfaces:**
- Produces: new fields `bypass_bridge_port` (`uint16_t`) on `struct bpf2socks_runtime_config` (`bpf2socks.h:155`), and a new LPM4 map handle for the FakeDNS pool CIDR, threaded into `build_ipv4_sock_addr_prog` (`connect_prog.c:1137`). Task 8 wires these from Kotlin.

This task requires reading, not writing blind — the exact map-population helper for existing CIDR maps (`direct_cidr4_map_fd`, `proxy_cidr4_map_fd`) is not yet identified in this plan and must not be guessed.

- [ ] **Step 1:** Read `bpf2socks/src/main/native/connect_prog.c` in full around `create_lpm4_map` (line 191) and `emit_ipv4_policy_checks_from_regs` (lines 597-682, specifically the `proxy_cidr4_map_fd` block at 618-626) to confirm the exact LPM4 key layout (`struct bpf2socks_lpm4_key { prefixlen; addr; }`) and byte order used when populating map entries. Also read `bpf2socks/src/main/native/main.c` and any `policy.c`/`bpf_util.c` code that currently populates `direct_cidr4_map_fd` from `policy->direct_cidr_path_v4` (grep for `direct_cidr_path_v4` across the `bpf2socks/src/main/native/` directory) to find the exact existing function that parses a CIDR string into an LPM4 map entry. Reuse that exact function for a single hardcoded entry `"198.18.0.0/15"` — do not write a second, parallel CIDR-parsing routine.
- [ ] **Step 2:** In `bpf2socks.h`, add to `struct bpf2socks_runtime_config` (line 155 area, next to the existing `uint16_t socks_port`):
  ```c
  uint16_t bypass_bridge_port;
  uint16_t bypass_socks_port;
  ```
- [ ] **Step 3:** In `connect_prog.c`, create the FakeDNS-pool LPM4 map at the same point `direct_cidr4_map_fd` is currently created (find this call site via the `create_lpm4_map` grep from Step 1), and populate it with the single `198.18.0.0/15` entry using the function identified in Step 1.
- [ ] **Step 4:** In `build_ipv4_sock_addr_prog` (`connect_prog.c:1137-1241`), thread a new `int fakedns_pool_cidr4_map_fd` parameter and a new `uint16_t bypass_bridge_port` parameter (mirroring how `proxy_cidr4_map_fd`/`bridge_port` are already threaded through this function's parameter list).
- [ ] **Step 5:** Modify `emit_uid_policy` (`connect_prog.c:254-308`) or the call site around it in `build_ipv4_sock_addr_prog` (line 1184) so that, for the jumps currently pushed into `bypass_jumps` (lines 271, 293, 302, 304 — all "this uid should bypass" jump points), instead of jumping directly to `allow_label`, they first fall through to a new check: if the destination in `BPF_REG_7`/`STACK_SAVED_V4_ADDR` matches `fakedns_pool_cidr4_map_fd` (LPM lookup, same instruction pattern as `emit_ipv4_policy_checks_from_regs`'s `proxy_cidr4_map_fd` block at lines 618-626), do **not** jump to `allow_label` — instead fall through to the same `emit_token_update_and_rewrite` redirect path the DNS-force-proxy case uses (`connect_prog.c:1211-1219`), but passing `bypass_bridge_port` instead of the normal `bridge_port` as the rewrite target. If the destination does not match, jump to `allow_label` exactly as today. This is a control-flow change (conditional branch replacing an unconditional jump) — read `emit_ipv4_dns_force_proxy_policy_from_regs` (lines 310-329) for the closest existing example of "conditionally redirect based on a runtime check, using `force_proxy_jumps` instead of an immediate unconditional bypass."
- [ ] **Step 6:** Apply the identical change to `build_ipv6_sock_addr_prog` only if an IPv6 FakeDNS pool exists — per Global Constraints it does not, so **skip IPv6** entirely for this task.
- [ ] **Step 7: Manual verification** (on a rooted test device, bpf2socks mode active):
  1. Confirm the native library still builds: run this project's existing native build task (check `bpf2socks/build.gradle.kts` for the exact Gradle task name, e.g. `./gradlew :bpf2socks:externalNativeBuildDebug`).
  2. Push the rebuilt `.so`, start bpf2socks mode, and check `logcat` for eBPF verifier errors during program load (`bpf2socks_bpf_probe`/`bpf2socks_bpf_start` — grep the log tag these functions use). Expected: no `EACCES`/`invalid indirect read`/`unreachable insn` errors — if any appear, the control-flow change in Step 5 produced a program the verifier rejects; simplify the branch structure and retry.
  3. With a blacklisted app active, confirm (via the same conntrack/log-based technique used earlier in this investigation) that its connections to `198.18.0.0/15` addresses now appear on the bypass bridge port rather than failing outright.
- [ ] **Step 8: Commit**
  ```bash
  git add bpf2socks/src/main/native/bpf2socks.h bpf2socks/src/main/native/connect_prog.c
  git commit -m "feat: redirect excluded uids' fakedns-pool connections instead of bypassing (bpf2socks)"
  ```

---

### Task 7: bpf2socks bridge daemon — second listener targeting the bypass-direct Xray inbound

**Files:**
- Modify: `bpf2socks/src/main/native/bridge_tcp.c`
- Modify: `bpf2socks/src/main/native/bridge_udp.c`
- Modify: `bpf2socks/src/main/native/main.c` (or wherever `bpf2socks_bridge_run` — `bpf2socks.h:358` — is implemented/started)

**Interfaces:**
- Consumes: `bypass_bridge_port`, `bypass_socks_port` from `struct bpf2socks_runtime_config` (Task 6 Step 2).

This task requires reading, not writing blind.

- [ ] **Step 1:** Read `bridge_tcp.c` end-to-end around the `connect(client_fd, ...)` call at line 186 and line 600, and `bridge_udp.c` around the `connect(fd, socks_addr, ...)` call at line 1394, to identify exactly how the bridge currently (a) listens for kernel-redirected connections on `config->socks_port`'s companion local bridge port, and (b) dials out to `config->socks_port` (Xray's SOCKS inbound) to relay them. Also read `bpf2socks_bridge_run`'s implementation (`bpf2socks.h:358` declares it; find the `.c` file defining it) to see how the listener socket(s) are set up and how many are created today.
- [ ] **Step 2:** Duplicate the existing listener setup (identified in Step 1) for a second pair of sockets bound to `config->bypass_bridge_port` (accept side) that relay to `config->bypass_socks_port` (the Xray bypass-direct SOCKS inbound) instead of `config->socks_port`. Do not duplicate business logic (limits, session tracking, token handling) — only the listen/accept/relay-target wiring should differ; reuse the exact same session/relay functions for both, parameterized by which target port to dial, exactly as the existing code already parameterizes by `config->socks_port` today (i.e., thread the target port as a parameter rather than hardcoding `config->socks_port` inside the shared relay function, if it is currently hardcoded — check before assuming).
- [ ] **Step 3: Manual verification:**
  1. Rebuild and confirm the daemon starts without crashing: check its own log output (path identified via `Bpf2SocksRootRunner.kt`'s log configuration) for a clean startup with both listeners bound.
  2. With a blacklisted app active and Task 6 in place, confirm the app's FakeDNS-pool connection is relayed to the bypass Xray inbound (correlate the local bridge port in `netstat`/`ss` output on-device with `RootBpf2SocksBypassBridgePort`).
- [ ] **Step 4: Commit**
  ```bash
  git add bpf2socks/src/main/native/bridge_tcp.c bpf2socks/src/main/native/bridge_udp.c bpf2socks/src/main/native/main.c
  git commit -m "feat: add bpf2socks bridge listener for the bypass-direct xray inbound"
  ```

---

### Task 8: Wire the bypass-direct path into bpf2socks mode (Kotlin)

**Files:**
- Modify: `app/src/main/kotlin/engine/bpf2socks/Bpf2SocksConfig.kt`
- Modify: `app/src/main/kotlin/engine/root/RootConfigSupport.kt` (only if `bpf2SocksBridgePortValue`-style helper needs a bypass counterpart)

**Interfaces:**
- Consumes: `buildRootBypassDirectInbound`, `buildXrayBypassDirectRule` (Task 2), `RootBpf2SocksBypassBridgePort`, `RootBpf2SocksBypassSocksPort`, `XrayTags.BPF2SOCKS_BYPASS_INBOUND` (Task 1), `bypass_bridge_port`/`bypass_socks_port` runtime config fields (Task 6/7).

- [ ] **Step 1:** In `Bpf2SocksConfig.kt`'s `buildBpf2SocksInbounds` (lines 152-165), add `add(buildRootBypassDirectInbound(XrayTags.BPF2SOCKS_BYPASS_INBOUND, RootBpf2SocksBypassSocksPort))`.
- [ ] **Step 2:** Thread `bypassDirectInboundTags = listOf(XrayTags.BPF2SOCKS_BYPASS_INBOUND)` through the same `buildRootStartConfig`/`buildXrayRoutingPlan` call site this file uses for `dnsHijackInboundTags = listOf(XrayTags.BPF2SOCKS_INBOUND)` (line 115), mirroring Task 4 Step 2.
- [ ] **Step 3:** Find where this file currently populates the native `bpf2socks_runtime_config`-equivalent JSON (the `bridgePort`/`socksPort` fields referenced at lines 49, 114, 127) and add `bypassBridgePort = RootBpf2SocksBypassBridgePort` / `bypassSocksPort = RootBpf2SocksBypassSocksPort` alongside them, matching whatever serialization shape the existing fields use (check for a `@Serializable data class` with `bridgePort`/`socksPort` properties feeding the native config).
- [ ] **Step 4:** Build: `./gradlew :app:compileDebugKotlin`. Expected: BUILD SUCCESSFUL.
- [ ] **Step 5: Manual verification** — same procedure as Task 4 Step 6 / Task 6 Step 7 / Task 7 Step 3, run end-to-end against bpf2socks mode.
- [ ] **Step 6: Commit**
  ```bash
  git add app/src/main/kotlin/engine/bpf2socks/Bpf2SocksConfig.kt app/src/main/kotlin/engine/root/RootConfigSupport.kt
  git commit -m "feat: route excluded apps' fakedns-pool connections to direct outbound (bpf2socks)"
  ```

---

### Task 9: Cross-mode regression pass

**Files:** none (verification-only task, no source changes expected; if it finds a regression, it produces a fix in whichever task's files are implicated, not new files of its own).

- [ ] **Step 1:** For each of the three modes (tproxy, tun2socks, bpf2socks), with **no** app excluded, confirm normal proxied traffic is unaffected: browse in a non-excluded app, confirm DNS still resolves via FakeDNS and the connection still routes through `XrayTags.PROXY` as before (check logs for `app/dispatcher: ... taking detour [proxy]` or equivalent).
- [ ] **Step 2:** For each of the three modes, with the same app excluded (blacklist) as used in the original bug report, confirm:
   - The app's domains still resolve to a `198.18.0.0/15` FakeDNS address at the DNS layer (expected, unchanged — this plan does not fix DNS attribution, only its consequence).
   - The app's real connections now succeed (not just "route direct" in logs — confirm actual app functionality, e.g. the app loads content).
- [ ] **Step 3:** Repeat Step 2 in whitelist mode with the same app left off the whitelist.
- [ ] **Step 4:** Confirm the `RootProxyAppWhitelistSystemUids` system UIDs (uid 0, 1052) are unaffected in whitelist mode — they should continue to bypass exactly as before, including for FakeDNS-pool destinations, since Task 3's whitelist branch already folds them into `allowed` before negating.
- [ ] **Step 5:** If any regression appears, do not patch it inline in this task — identify which numbered task's files are implicated and dispatch a fix against that task's commit.

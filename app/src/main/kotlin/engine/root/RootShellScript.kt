// Copyright 2026, AsteriskNG contributors
// SPDX-License-Identifier: GPL-3.0

package engine.root

import app.modes.ProxyAppListModeBlacklist
import app.modes.ProxyAppListModeWhitelist
import engine.xray.XrayFakeDnsIpv4Pool
import utils.shellQuote

internal fun StringBuilder.appendScript(script: String) {
    append(script.trimIndent())
    append('\n')
}

/** Indents a complete shell fragment before embedding it inside a function or subshell. */
internal fun String.indentShellBlock(prefix: String = "    "): String {
    return trim()
        .lineSequence()
        .joinToString("\n") { line -> if (line.isBlank()) "" else "$prefix$line" }
}

internal fun StringBuilder.appendHeredoc(
    targetPath: String,
    content: String,
) {
    appendScript("cat > ${targetPath.shellQuote()} <<'$BootScriptHeredocDelimiter'")
    append(content)
    if (!content.endsWith('\n')) {
        append('\n')
    }
    appendScript(BootScriptHeredocDelimiter)
}

internal fun StringBuilder.appendDeleteRuleLoop(
    command: String,
    chain: String,
    rule: String,
    table: String = "mangle",
) {
    appendScript("while $command -t $table -D $chain $rule 2>/dev/null; do :; done")
}

internal fun StringBuilder.appendIpRuleDeleteLoop(
    ipCommand: String,
    rule: String,
) {
    appendScript("while $ipCommand rule del $rule 2>/dev/null; do :; done")
}

internal fun StringBuilder.appendRootEbpfXtbpfMarkRules(
    command: String,
    chain: String,
    routeMark: String,
    ownerBypassGid: Int? = null,
) {
    val ownerMatch = ownerBypassGid?.let { gid -> "-m owner ! --gid-owner $gid " }.orEmpty()
    val quotedProgramPath = command.rootEbpfProgramPath(
        ipv4Path = RootEbpfXtOutputV4ProgramPath,
        ipv6Path = RootEbpfXtOutputV6ProgramPath,
    ).shellQuote()
    appendScript(
        """
        $command -t mangle -A $chain -p tcp ${ownerMatch}-m bpf --object-pinned $quotedProgramPath -j MARK --set-xmark $routeMark
        $command -t mangle -A $chain -p udp ${ownerMatch}-m bpf --object-pinned $quotedProgramPath -j MARK --set-xmark $routeMark
        """,
    )
}

internal fun StringBuilder.appendRootEbpfXtbpfInterfaceMarkRules(
    command: String,
    chain: String,
    routeMark: String,
    interfacePrefixes: List<String>,
) {
    val quotedProgramPath = command.rootEbpfProgramPath(
        ipv4Path = RootEbpfXtPreroutingV4ProgramPath,
        ipv6Path = RootEbpfXtPreroutingV6ProgramPath,
    ).shellQuote()
    interfacePrefixes.forEach { prefix ->
        val quotedInterface = prefix.shellQuote()
        appendScript(
            """
            $command -t mangle -A $chain -i $quotedInterface -p tcp -m bpf --object-pinned $quotedProgramPath -j MARK --set-xmark $routeMark
            $command -t mangle -A $chain -i $quotedInterface -p udp -m bpf --object-pinned $quotedProgramPath -j MARK --set-xmark $routeMark
            """,
        )
    }
}

internal fun StringBuilder.appendRootEbpfXtbpfInterfaceTproxyRules(
    command: String,
    chain: String,
    interfacePrefixes: List<String>,
    port: Int,
    onIp: String,
    mark: String,
) {
    val quotedProgramPath = command.rootEbpfProgramPath(
        ipv4Path = RootEbpfXtPreroutingV4ProgramPath,
        ipv6Path = RootEbpfXtPreroutingV6ProgramPath,
    ).shellQuote()
    interfacePrefixes.forEach { prefix ->
        val quotedInterface = prefix.shellQuote()
        appendScript(
            """
            $command -t mangle -A $chain -i $quotedInterface -p tcp -m bpf --object-pinned $quotedProgramPath -j TPROXY --on-port $port --on-ip $onIp --tproxy-mark $mark
            $command -t mangle -A $chain -i $quotedInterface -p udp -m bpf --object-pinned $quotedProgramPath -j TPROXY --on-port $port --on-ip $onIp --tproxy-mark $mark
            """,
        )
    }
}

internal fun StringBuilder.appendAsteriskdBypassAnchorJump(
    command: String,
    chain: String,
    ipv6: Boolean,
) {
    val anchor = if (ipv6) RootAsteriskdBypass6Anchor else RootAsteriskdBypass4Anchor
    appendScript("$command -t mangle -N $anchor 2>/dev/null || true")
    appendScript("$command -t mangle -A $chain -j $anchor")
}

internal fun StringBuilder.appendAsteriskdBypassAnchorCleanup(
    command: String,
    ipv6: Boolean,
) {
    val chains = if (ipv6) {
        listOf(RootAsteriskdBypass6SlotA, RootAsteriskdBypass6SlotB, RootAsteriskdBypass6Anchor)
    } else {
        listOf(RootAsteriskdBypass4SlotA, RootAsteriskdBypass4SlotB, RootAsteriskdBypass4Anchor)
    }
    chains.forEach { chain ->
        appendScript(
            """
            $command -t mangle -F $chain 2>/dev/null || true
            $command -t mangle -X $chain 2>/dev/null || true
            """,
        )
    }
}

private fun String.rootEbpfProgramPath(ipv4Path: String, ipv6Path: String): String {
    return if (this == RootIp6tablesCommand) ipv6Path else ipv4Path
}

internal fun StringBuilder.appendRootIpv6DnsRejectRules(cleanupExistingRules: Boolean = true) {
    if (cleanupExistingRules) {
        appendRootIpv6DnsRejectCleanupRules()
    }
    appendScript(
        """
        $RootIp6tablesCommand -t mangle -I PREROUTING 1 -p udp --dport 53 -j DROP
        $RootIp6tablesCommand -t filter -I INPUT 1 -p udp --dport 53 -j REJECT
        $RootIp6tablesCommand -t filter -I FORWARD 1 -p udp --dport 53 -j REJECT
        $RootIp6tablesCommand -t filter -I OUTPUT 1 -p udp --dport 53 -j REJECT
        """,
    )
}

internal fun StringBuilder.appendRootIpv6DnsRejectCleanupRules() {
    appendDeleteRuleLoop(
        command = RootIp6tablesCommand,
        chain = "PREROUTING",
        rule = "-p udp --dport 53 -j DROP",
        table = "mangle",
    )
    appendDeleteRuleLoop(
        command = RootIp6tablesCommand,
        chain = "INPUT",
        rule = "-p udp --dport 53 -j REJECT",
        table = "filter",
    )
    appendDeleteRuleLoop(
        command = RootIp6tablesCommand,
        chain = "FORWARD",
        rule = "-p udp --dport 53 -j REJECT",
        table = "filter",
    )
    appendDeleteRuleLoop(
        command = RootIp6tablesCommand,
        chain = "OUTPUT",
        rule = "-p udp --dport 53 -j REJECT",
        table = "filter",
    )
}

internal fun StringBuilder.appendRootFakeDnsIcmpReplyRules(cleanupExistingRules: Boolean = true) {
    if (cleanupExistingRules) {
        appendRootFakeDnsIcmpReplyCleanupRules()
    }
    val pool = XrayFakeDnsIpv4Pool.shellQuote()
    appendScript(
        """
        $RootIptablesCommand -t nat -N $RootFakeDnsIcmpReplyChain 2>/dev/null || true
        $RootIptablesCommand -t nat -N $RootFakeDnsIcmpReplyPreroutingChain 2>/dev/null || true
        $RootIptablesCommand -t nat -I OUTPUT 1 -j $RootFakeDnsIcmpReplyChain
        $RootIptablesCommand -t nat -I PREROUTING 1 -j $RootFakeDnsIcmpReplyPreroutingChain
        $RootIptablesCommand -t nat -A $RootFakeDnsIcmpReplyChain -d $pool -p icmp --icmp-type echo-request -j REDIRECT
        $RootIptablesCommand -t nat -A $RootFakeDnsIcmpReplyPreroutingChain -d $pool -p icmp --icmp-type echo-request -j REDIRECT
        """,
    )
}

internal fun StringBuilder.appendRootFakeDnsIcmpReplyCleanupRules() {
    appendDeleteRuleLoop(RootIptablesCommand, "OUTPUT", "-j $RootFakeDnsIcmpReplyChain", table = "nat")
    appendDeleteRuleLoop(RootIptablesCommand, "PREROUTING", "-j $RootFakeDnsIcmpReplyPreroutingChain", table = "nat")
    appendScript(
        """
        $RootIptablesCommand -t nat -F $RootFakeDnsIcmpReplyChain 2>/dev/null || true
        $RootIptablesCommand -t nat -X $RootFakeDnsIcmpReplyChain 2>/dev/null || true
        $RootIptablesCommand -t nat -F $RootFakeDnsIcmpReplyPreroutingChain 2>/dev/null || true
        $RootIptablesCommand -t nat -X $RootFakeDnsIcmpReplyPreroutingChain 2>/dev/null || true
        """,
    )
}

/**
 * For excluded UIDs, redirects (rather than bypasses) connections whose destination falls
 * inside the FakeDNS pool CIDR. A bypassed app's own DNS never reaches this pool correctly
 * attributed (netd resolves DNS under its own uid, not the app's, so DNS traffic can never be
 * correctly attributed to the excluded app's uid via -m owner --uid-owner matching) so the
 * app is handed a synthetic FakeDNS IP regardless of exclusion. Its real data connection,
 * opened by the app's own socket, IS correctly attributable — so instead of letting that
 * connection dial the synthetic IP directly (which always fails), this sends it into a
 * dedicated tunnel inbound that sniffs the real domain and redials it, then routes straight
 * to the direct/freedom outbound.
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

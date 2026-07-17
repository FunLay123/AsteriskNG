// Copyright 2026, AsteriskNG contributors
// SPDX-License-Identifier: GPL-3.0

package engine.root

import app.modes.ProxyAppListModeBlacklist
import app.modes.ProxyAppListModeWhitelist
import engine.xray.XrayFakeDnsIpv4Pool
import utils.shellQuote

/**
 * DNATs DNS traffic for UIDs that should bypass the proxy entirely, so their queries never
 * reach the local FakeDNS/TPROXY resolver in the first place. Owner-match reliably identifies
 * the originating app only in OUTPUT/POSTROUTING (nat OUTPUT here), which is why this must
 * happen before any mangle-table marking or PREROUTING-based interception.
 *
 * Note: on modern Android, apps normally don't open the UDP:53 socket themselves — the system
 * resolver (netd) does it on their behalf, usually under its own uid. If that's the case here,
 * this rule (keyed on the app's own uid) won't match those packets either, since the owning uid
 * of the socket won't be the app's. Verify with `cat /proc/net/udp | grep :0035` while the
 * excluded app is active before assuming this fixes it.
 */
internal fun StringBuilder.appendOutputDnsBypassNatRules(
    command: String,
    chain: String,
    mode: Int,
    forcedBypassUids: List<Int>,
    uids: List<Int>,
    whitelistSystemUids: List<Int>,
    realDnsServer: String,
) {
    fun appendBypassForUid(uid: Int) {
        appendScript(
            """
            $command -t nat -A $chain -m owner --uid-owner $uid -p udp --dport 53 -j DNAT --to-destination ${realDnsServer.shellQuote()}
            $command -t nat -A $chain -m owner --uid-owner $uid -p tcp --dport 53 -j DNAT --to-destination ${realDnsServer.shellQuote()}
            """,
        )
    }
    forcedBypassUids.distinct().forEach(::appendBypassForUid)
    when (mode) {
        ProxyAppListModeBlacklist -> uids.distinct().forEach(::appendBypassForUid)
        ProxyAppListModeWhitelist -> {
            val allowed = (uids.distinct() + whitelistSystemUids).distinct()
            if (allowed.isNotEmpty()) {
                val negatedOwners = allowed.joinToString(" ") { uid -> "-m owner ! --uid-owner $uid" }
                appendScript(
                    """
                    $command -t nat -A $chain $negatedOwners -p udp --dport 53 -j DNAT --to-destination ${realDnsServer.shellQuote()}
                    $command -t nat -A $chain $negatedOwners -p tcp --dport 53 -j DNAT --to-destination ${realDnsServer.shellQuote()}
                    """,
                )
            }
        }
        else -> Unit
    }
}

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
        listOf(RootAsteriskdBypass6Anchor, RootAsteriskdBypass6SlotA, RootAsteriskdBypass6SlotB)
    } else {
        listOf(RootAsteriskdBypass4Anchor, RootAsteriskdBypass4SlotA, RootAsteriskdBypass4SlotB)
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

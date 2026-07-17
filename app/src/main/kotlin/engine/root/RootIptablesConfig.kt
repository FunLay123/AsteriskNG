// Copyright 2026, AsteriskNG contributors
// SPDX-License-Identifier: GPL-3.0

package engine.root

import android.content.Context
import android.os.Process
import app.AppState
import app.modes.ProxyAppListModeGlobal
import engine.network.isIpAddress
import engine.network.isIpv4Address
import engine.network.isIpv6Address
import utils.toTrimmedNonEmptyDistinctList

internal data class RootIptablesConfig(
    val mark: String,
    val ipv4Table: String,
    val ipv6Table: String,
    val enableEbpfRules: Boolean = false,
    val enableEbpfDirectCidrBypass: Boolean = false,
    val externalInterfacePrefixes: List<String> = emptyList(),
    val ignoredInterfaces: List<String> = emptyList(),
    val proxyPrivateIpv4Cidrs: List<String> = emptyList(),
    val proxyPrivateIpv6Cidrs: List<String> = emptyList(),
    val bypassPrivateIpv4Cidrs: List<String> = emptyList(),
    val bypassPrivateIpv6Cidrs: List<String> = emptyList(),
    val forcedBypassUids: List<Int> = emptyList(),
    val proxyAppListMode: Int = ProxyAppListModeGlobal,
    val proxyApplicationUids: List<Int> = emptyList(),
    val dnsBypassServerIpv4: String = RootDnsBypassServerIpv4,
    val dnsBypassServerIpv6: String = RootDnsBypassServerIpv6,
)

internal fun RootIptablesConfig.withAppSettings(
    context: Context,
    appState: AppState,
): RootIptablesConfig {
    val proxyPrivateCidrs = appState.privateAddressCidrs.toTrimmedNonEmptyDistinctList()
    val bypassPrivateCidrs = RootDefaultBypassPrivateCidrs.toTrimmedNonEmptyDistinctList()
    val selectedAppKeys = appState.proxyAppListSelectedApps.toTrimmedNonEmptyDistinctList()
    val appListMode = if (selectedAppKeys.isEmpty()) {
        ProxyAppListModeGlobal
    } else {
        appState.proxyAppListMode.toRootProxyAppListMode()
    }
    // Prefer the DNS servers the user configured in the app's own DNS settings (direct, then
    // proxy) for the real destination we DNAT excluded/bypassed apps' DNS queries to. A DNAT
    // target must be a literal IP (there's no resolver available to look up a hostname at this
    // point), so entries that aren't already an IP (e.g. DoH endpoints by domain) are skipped.
    val userConfiguredDnsServers = (appState.directDns + appState.proxyDns).toTrimmedNonEmptyDistinctList()

    return copy(
        externalInterfacePrefixes = appState.externalInterfaces.toTrimmedNonEmptyDistinctList(),
        ignoredInterfaces = appState.ignoredInterfaces.toTrimmedNonEmptyDistinctList(),
        proxyPrivateIpv4Cidrs = proxyPrivateCidrs.ipv4Cidrs(),
        proxyPrivateIpv6Cidrs = proxyPrivateCidrs.ipv6Cidrs(),
        bypassPrivateIpv4Cidrs = bypassPrivateCidrs.ipv4Cidrs(),
        bypassPrivateIpv6Cidrs = bypassPrivateCidrs.ipv6Cidrs(),
        forcedBypassUids = listOf(Process.myUid()),
        proxyAppListMode = appListMode,
        proxyApplicationUids = if (appListMode == ProxyAppListModeGlobal) {
            emptyList()
        } else {
            context.resolveRootProxyApplicationUids(selectedAppKeys)
        },
        enableEbpfRules = appState.enableRootEbpfRules,
        enableEbpfDirectCidrBypass = appState.enableRootEbpfDirectCidrBypass,
        dnsBypassServerIpv4 = userConfiguredDnsServers.firstPlainIpv4DnsHost()
            ?.let { host -> "$host:53" }
            ?: RootDnsBypassServerIpv4,
        dnsBypassServerIpv6 = userConfiguredDnsServers.firstPlainIpv6DnsHost()
            ?.let { host -> "[$host]:53" }
            ?: RootDnsBypassServerIpv6,
    )
}

private fun List<String>.ipv4Cidrs(): List<String> {
    return filterNot { cidr -> ":" in cidr }
}

private fun List<String>.ipv6Cidrs(): List<String> {
    return filter { cidr -> ":" in cidr }
}

/** Extracts a literal IP from a DNS server entry, stripping any scheme (udp://, tls://,
 *  quic+local://, https://…) and path/port suffix. Returns null if the host isn't a plain
 *  IP (e.g. a DoH domain), since that can't be used as a DNAT target. */
private fun String.extractPlainDnsHost(): String? {
    var value = trim()
    val schemeIndex = value.indexOf("://")
    if (schemeIndex >= 0) {
        value = value.substring(schemeIndex + 3)
    }
    value = value.substringBefore("/")
    if (value.startsWith("[")) {
        return value.substringAfter("[").substringBefore("]").takeIf(::isIpv6Address)
    }
    val lastColon = value.lastIndexOf(":")
    if (lastColon > 0) {
        val hostPart = value.substring(0, lastColon)
        val portPart = value.substring(lastColon + 1)
        if (portPart.isNotEmpty() && portPart.all(Char::isDigit) && isIpAddress(hostPart)) {
            return hostPart
        }
    }
    return value.takeIf(::isIpAddress)
}

private fun List<String>.firstPlainIpv4DnsHost(): String? {
    return firstNotNullOfOrNull { entry -> entry.extractPlainDnsHost()?.takeIf(::isIpv4Address) }
}

private fun List<String>.firstPlainIpv6DnsHost(): String? {
    return firstNotNullOfOrNull { entry -> entry.extractPlainDnsHost()?.takeIf(::isIpv6Address) }
}

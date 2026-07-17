// Copyright 2026, AsteriskNG contributors
// SPDX-License-Identifier: GPL-3.0

package engine.root

import android.content.Context
import app.AppState
import app.ProxyServerState
import app.effectiveFakeDnsEnabled
import app.effectiveLocalDnsEnabled
import engine.network.toPortOrNull
import engine.proxy.ProxyEngineStartRequest
import engine.tun2socks.DefaultTun2SocksProxyPort
import engine.vpn.xrayDnsHosts
import engine.xray.XrayConfigFactory
import engine.xray.XrayConfigRequest
import engine.xray.XrayCoreLogPaths
import engine.xray.XrayProtocols
import engine.xray.buildXrayOutboundPlan
import engine.xray.prepareXrayCoreLogPaths
import engine.xray.toJsonStringArray
import engine.xray.validateXrayExternalRoutingResources
import features.resources.runtime.XrayResourceFilePaths
import features.resources.runtime.prepareXrayResourceFilePaths
import features.proxy.server.model.Custom
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

internal class RootConfigBuildContext(
    private val androidContext: Context,
    val appState: AppState,
    private val selectedServer: ProxyServerState,
    val resourceFilePaths: XrayResourceFilePaths,
    private val coreLogPaths: XrayCoreLogPaths,
    private val dnsHosts: List<String>,
) {
    fun buildRootStartConfig(
        inbounds: List<JsonObject>,
        dnsHijackInboundTags: List<String>,
        bypassDirectInboundTags: List<String> = emptyList(),
    ): RootStartConfig {
        val xrayConfigJson = XrayConfigFactory.buildXrayConfig(
            XrayConfigRequest(
                appState = appState,
                selectedServer = selectedServer,
                inbounds = inbounds,
                coreLogPaths = coreLogPaths,
                dnsHosts = dnsHosts,
                dnsHijackInboundTags = dnsHijackInboundTags,
                bypassDirectInboundTags = bypassDirectInboundTags,
            ),
        )
        return appState.toRootStartConfig(
            xrayConfigJson = xrayConfigJson,
            resourceFilePaths = resourceFilePaths,
            runtimeLayout = resourceFilePaths.toRootRuntimeLayout(),
            coreLogPaths = coreLogPaths,
        )
    }

    fun buildRootIptablesConfig(
        base: RootIptablesConfig,
    ): RootIptablesConfig {
        return base.withAppSettings(
            context = androidContext,
            appState = appState,
        )
    }

    fun buildRootEbpfRuntimeConfig(iptablesConfig: RootIptablesConfig): RootEbpfRuntimeConfig? {
        if (!iptablesConfig.enableEbpfRules) return null
        val runtimeLayout = resourceFilePaths.toRootRuntimeLayout()
        return RootEbpfRuntimeConfig(
            matcherPath = runtimeLayout.bpfMatcherPath,
            bpfPolicyPath = runtimeLayout.bpfPolicyPath,
            directCidrPathV4 = runtimeLayout.rootEbpfDirectCidrPathV4,
            directCidrPathV6 = runtimeLayout.rootEbpfDirectCidrPathV6,
            directCidrSourcePathsV4 = listOf(resourceFilePaths.directCidrIpv4Path),
            directCidrSourcePathsV6 = listOf(resourceFilePaths.directCidrIpv6Path),
            policy = iptablesConfig.toRootEbpfPolicy(
                enableIpv6 = appState.enableIpv6,
                directCidrPathV4 = runtimeLayout.rootEbpfDirectCidrPathV4,
                directCidrPathV6 = runtimeLayout.rootEbpfDirectCidrPathV6,
                xtOutputV4ProgramPath = RootEbpfXtOutputV4ProgramPath,
                xtOutputV6ProgramPath = RootEbpfXtOutputV6ProgramPath,
                xtPreroutingV4ProgramPath = RootEbpfXtPreroutingV4ProgramPath,
                xtPreroutingV6ProgramPath = RootEbpfXtPreroutingV6ProgramPath,
            ),
        )
    }

}

internal fun Context.prepareRootConfigBuildContext(request: ProxyEngineStartRequest): RootConfigBuildContext {
    val appState = request.appState
    val resourceFilePaths = prepareXrayResourceFilePaths()
    if (request.selectedServer.server !is Custom) {
        appState.validateXrayExternalRoutingResources(resourceFilePaths.dataDir)
    }
    val coreLogPaths = prepareXrayCoreLogPaths()
    val outboundPlan = appState.buildXrayOutboundPlan(request.selectedServer)
    return RootConfigBuildContext(
        androidContext = applicationContext,
        appState = appState,
        selectedServer = request.selectedServer,
        resourceFilePaths = resourceFilePaths,
        coreLogPaths = coreLogPaths,
        dnsHosts = appState.xrayDnsHosts(outboundPlan.dnsHostServers),
    )
}

private fun AppState.toRootStartConfig(
    xrayConfigJson: String,
    resourceFilePaths: XrayResourceFilePaths,
    runtimeLayout: RootRuntimeLayout,
    coreLogPaths: XrayCoreLogPaths,
): RootStartConfig {
    return RootStartConfig(
        xrayConfigJson = xrayConfigJson,
        setuidgidPath = resourceFilePaths.setuidgidPath,
        runtimeLayout = runtimeLayout,
        enableIpv6 = enableIpv6,
        enableRootIpv6Disabler = enableRootIpv6Disabler,
        enableLocalDns = effectiveLocalDnsEnabled,
        enableFakeDns = effectiveFakeDnsEnabled,
        enableAccessLog = enableAccessLog,
        coreLogPaths = coreLogPaths,
    )
}

internal fun AppState.buildRootSharedProxyInbounds(
    httpInboundTag: String,
): List<JsonObject> {
    return buildList {
        httpProxyPort.toPortOrNull()
            ?.takeIf { enableHttpProxy }
            ?.let { port -> add(buildRootHttpProxyInbound(httpInboundTag, port)) }
    }
}

internal fun AppState.tun2SocksInternalProxyPortValue(): Int {
    return socks5ProxyPort.toPortOrNull() ?: DefaultTun2SocksProxyPort
}

internal fun AppState.bpf2SocksBridgePortValue(): Int {
    return bpf2SocksBridgePort.toPortOrNull() ?: RootBpf2SocksDefaultBridgePort
}

private fun buildRootHttpProxyInbound(
    tag: String,
    port: Int,
): JsonObject {
    return buildJsonObject {
        put("tag", tag)
        put("listen", RootSharedProxyListenAddress)
        put("port", port)
        put("protocol", XrayProtocols.HTTP)
        put(
            "settings",
            buildJsonObject {
                put("allowTransparent", false)
                put("userLevel", 0)
            },
        )
    }
}

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

package io.github.henriqk0.passwsync.platform

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import io.github.henriqk0.passwsync.CoreExecutor
import io.github.henriqk0.passwsync.core.PasswsyncCore

/**
 * Classifies the networks the platform reports (FR-039): only Wi-Fi or Ethernet networks that
 * are not a VPN are local; their interface names are handed to the core, which filters its own
 * interface scan with them. Mobile data and VPN interfaces are never eligible. An empty set is
 * "no local network". Nothing is resolved or connected here; networking belongs to Rust (S7).
 */
class NetworkClassifier(
    context: Context,
    private val core: PasswsyncCore,
    private val executor: CoreExecutor,
    private val changed: () -> Unit,
) {
    private val connectivity: ConnectivityManager = context.getSystemService(ConnectivityManager::class.java)
    private val interfaces = HashMap<Network, String>()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            val name = properties.interfaceName
            synchronized(interfaces) {
                if (name == null) interfaces.remove(network) else interfaces[network] = name
            }
            publish()
        }

        override fun onLost(network: Network) {
            synchronized(interfaces) { interfaces.remove(network) }
            publish()
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivity.registerNetworkCallback(request, callback)
    }

    fun stop() {
        connectivity.unregisterNetworkCallback(callback)
    }

    private fun publish() {
        val names = synchronized(interfaces) { interfaces.values.distinct().sorted() }
        executor.run({ core.setEligibleInterfaces(names) }) { changed() }
    }
}

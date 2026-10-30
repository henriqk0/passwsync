package io.github.henriqk0.passwsync.screens

import android.view.View
import android.widget.Button
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.SecureDialogs
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.NetStateView
import io.github.henriqk0.passwsync.core.NetworkView
import io.github.henriqk0.passwsync.core.SettingsView
import io.github.henriqk0.passwsync.platform.LocalNetworkPermission

/**
 * The networking switch (off by default, FR-038), this device's name and fingerprint, the
 * "no local network" state and the identity reset (FR-037). Switching on needs a confirmation;
 * the API 37 local-network permission is asked only after it.
 */
class Network(activity: MainActivity) : Screen(activity, R.layout.network) {
    override fun bind() {
        find<Button>(R.id.networking_on_button).setOnClickListener {
            SecureDialogs.confirm(activity, R.string.networking_on_confirm_title, R.string.networking_on_confirm, R.string.networking_on) {
                LocalNetworkPermission.requestAfterConfirmation(activity)
                executor.run({ core.setNetworking(true, true) }) { result -> result.onSuccess { refresh() }.onFailure(::showError) }
            }
        }
        find<Button>(R.id.networking_off_button).setOnClickListener {
            executor.run({ core.setNetworking(false, false) }) { result -> result.onSuccess { refresh() }.onFailure(::showError) }
        }
        find<Button>(R.id.devices_button).setOnClickListener { activity.show(Devices(activity)) }
        find<Button>(R.id.pairing_button).setOnClickListener { activity.show(Pairing(activity)) }
        find<Button>(R.id.reset_identity_button).setOnClickListener {
            SecureDialogs.confirm(activity, R.string.reset_identity_confirm_title, R.string.reset_identity_confirm, R.string.reset_identity) {
                executor.run({ core.resetIdentity() }) { result -> result.onSuccess { refresh() }.onFailure(::showError) }
            }
        }
    }

    override fun refresh() {
        executor.run({ Pair(core.network(), core.settings()) }) { result ->
            result.onSuccess { (network, settings) -> render(network, settings) }.onFailure(::showError)
        }
    }

    override fun onEvent(event: CoreEvent) {
        if (event is CoreEvent.NetworkChanged) refresh() else super.onEvent(event)
    }

    private fun render(network: NetworkView, settings: SettingsView) {
        clearError()
        find<TextView>(R.id.network_state).setText(stateText(network.state))
        find<TextView>(R.id.this_device).text = network.thisDevice?.let {
            activity.getString(R.string.this_device_format, it.name, it.fingerprint)
        } ?: ""
        find<View>(R.id.no_local_network_text).visibility =
            if (network.state == NetStateView.NO_LOCAL_NETWORK) View.VISIBLE else View.GONE
        find<View>(R.id.networking_on_button).visibility = if (settings.networking) View.GONE else View.VISIBLE
        find<View>(R.id.networking_off_button).visibility = if (settings.networking) View.VISIBLE else View.GONE
        find<TextView>(R.id.networking_restart).text =
            if (settings.restartRequired) activity.getString(R.string.restart_required) else ""
    }

    private fun stateText(state: NetStateView): Int = when (state) {
        NetStateView.OFF -> R.string.net_state_off
        NetStateView.IDENTITY_UNUSABLE -> R.string.net_state_identity_unusable
        NetStateView.PEERS_UNUSABLE -> R.string.net_state_peers_unusable
        NetStateView.PORT_IN_USE -> R.string.net_state_port_in_use
        NetStateView.NO_LOCAL_NETWORK -> R.string.no_local_network
        NetStateView.ON -> R.string.net_state_on
        NetStateView.PAUSED -> R.string.net_state_paused
    }
}

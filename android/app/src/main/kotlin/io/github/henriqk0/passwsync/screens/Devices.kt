package io.github.henriqk0.passwsync.screens

import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.SecureDialogs
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.PeerView

/** Paired devices with their fingerprint and status; revoke after a confirmation (FR-050). */
class Devices(activity: MainActivity) : Screen(activity, R.layout.devices) {
    override fun bind() = Unit

    override fun refresh() {
        executor.run({ core.network().paired }) { result -> result.onSuccess(::render).onFailure(::showError) }
    }

    override fun onEvent(event: CoreEvent) {
        if (event is CoreEvent.NetworkChanged) refresh() else super.onEvent(event)
    }

    private fun render(paired: List<PeerView>) {
        clearError()
        find<View>(R.id.devices_empty).visibility = if (paired.isEmpty()) View.VISIBLE else View.GONE
        val list = find<LinearLayout>(R.id.devices_list)
        list.removeAllViews()
        for (peer in paired) {
            list.addView(
                Button(activity).apply {
                    text = activity.getString(R.string.device_format, peer.device.name, peer.device.fingerprint, peer.status)
                    setOnClickListener { revoke(peer) }
                },
            )
        }
    }

    private fun revoke(peer: PeerView) {
        SecureDialogs.confirm(activity, R.string.revoke_confirm_title, R.string.revoke_confirm, R.string.revoke) {
            executor.run({ core.revokeDevice(peer.device.id) }) { result -> result.onSuccess { refresh() }.onFailure(::showError) }
        }
    }
}

package io.github.henriqk0.passwsync.screens

import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.NearbyView
import io.github.henriqk0.passwsync.core.PairingView

/**
 * 003 pairing (FR-050, FR-053): show a code, or pick a nearby device and type its code (a
 * password-style field, X4); both sides compare names and fingerprints before the initiator
 * accepts. No wallet and no master password are involved. Leaving the app cancels it.
 */
class Pairing(activity: MainActivity) : Screen(activity, R.layout.pairing) {
    private var chosen: String? = null
    private var lastPeer: String? = null

    override fun bind() {
        find<Button>(R.id.start_pairing_button).setOnClickListener {
            executor.run({ core.startPairing() }) { result -> result.onSuccess(::render).onFailure(::showError) }
        }
        find<Button>(R.id.accept_pairing_button).setOnClickListener {
            val peer = lastPeer ?: return@setOnClickListener
            executor.run({ core.acceptPairing(peer) }) { result -> result.onSuccess { refresh() }.onFailure(::showError) }
        }
        find<Button>(R.id.reject_pairing_button).setOnClickListener { executor.run({ core.rejectPairing() }) { refresh() } }
        find<Button>(R.id.cancel_pairing_button).setOnClickListener { executor.run({ core.cancelPairing() }) { refresh() } }
        find<Button>(R.id.join_pairing_button).setOnClickListener { join() }
    }

    override fun refresh() {
        executor.run({ Pair(core.pairing(), core.network().nearby) }) { result ->
            result.onSuccess { (pairing, nearby) ->
                render(pairing)
                renderNearby(nearby)
            }.onFailure(::showError)
        }
    }

    override fun onEvent(event: CoreEvent) {
        if (event is CoreEvent.PairingChanged || event is CoreEvent.NetworkChanged) refresh() else super.onEvent(event)
    }

    override fun leave() {
        find<EditText>(R.id.pairing_code_entry).text.clear()
    }

    private fun render(view: PairingView) {
        clearError()
        find<TextView>(R.id.pairing_code).text = view.code ?: ""
        find<TextView>(R.id.pairing_state).text = view.state.name
        lastPeer = view.peer?.id
        find<TextView>(R.id.pairing_peer).text = view.peer?.let {
            activity.getString(R.string.this_device_format, it.name, it.fingerprint)
        } ?: ""
    }

    private fun renderNearby(nearby: List<NearbyView>) {
        val list = find<LinearLayout>(R.id.nearby_list)
        list.removeAllViews()
        for (device in nearby.filter { !it.paired }) {
            list.addView(
                Button(activity).apply {
                    text = activity.getString(R.string.nearby_format, device.device.fingerprint, device.address)
                    setOnClickListener { chosen = device.device.id }
                },
            )
        }
    }

    private fun join() {
        clearError()
        val peer = chosen ?: return
        val code = Secrets.take(find<EditText>(R.id.pairing_code_entry))
        executor.run({ Secrets.use(code) { core.joinPairing(peer, code) } }) { result ->
            result.onSuccess { refresh() }.onFailure(::showError)
        }
    }
}

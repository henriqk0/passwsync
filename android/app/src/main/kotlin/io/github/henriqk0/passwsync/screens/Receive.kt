package io.github.henriqk0.passwsync.screens

import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.PeerView

/** 005 recipient (FR-052): pick the paired sender and type its code (a password-style field). */
class Receive(activity: MainActivity) : Screen(activity, R.layout.receive) {
    private var sender: String? = null

    override fun bind() {
        find<Button>(R.id.redeem_button).setOnClickListener { redeem() }
    }

    override fun refresh() {
        executor.run({ core.network().paired }) { result -> result.onSuccess(::render).onFailure(::showError) }
    }

    override fun onEvent(event: CoreEvent) {
        if (event is CoreEvent.ShareChanged) activity.replace(Received(activity)) else super.onEvent(event)
    }

    override fun leave() {
        find<EditText>(R.id.invite_code_entry).text.clear()
    }

    private fun render(paired: List<PeerView>) {
        val list = find<LinearLayout>(R.id.receive_devices)
        list.removeAllViews()
        for (peer in paired) {
            list.addView(
                Button(activity).apply {
                    text = activity.getString(R.string.this_device_format, peer.device.name, peer.device.fingerprint)
                    setOnClickListener { sender = peer.device.id }
                },
            )
        }
    }

    private fun redeem() {
        clearError()
        val from = sender ?: return
        val code = Secrets.take(find<EditText>(R.id.invite_code_entry))
        executor.run({ Secrets.use(code) { core.redeemInvitation(from, code) } }) { result ->
            result.onFailure(::showError)
        }
    }
}

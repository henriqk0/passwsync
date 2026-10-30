package io.github.henriqk0.passwsync.screens

import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.SecureDialogs
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.InvitationState
import io.github.henriqk0.passwsync.core.InvitationView
import io.github.henriqk0.passwsync.core.PeerView

/**
 * 005 invitation (FR-052): pick a paired device, show the single-use code, then confirm the
 * recipient by name and fingerprint before the encrypted wallet is sent. Leaving the app
 * cancels an invitation whose transfer has not started (FR-051).
 */
class Share(activity: MainActivity, private val wallet: String) : Screen(activity, R.layout.share) {
    override fun bind() {
        find<TextView>(R.id.share_wallet).text = wallet
        find<Button>(R.id.accept_recipient_button).setOnClickListener { confirmRecipient() }
        find<Button>(R.id.cancel_invitation_button).setOnClickListener {
            executor.run({ core.cancelInvitation() }) { refresh() }
        }
    }

    override fun refresh() {
        executor.run({ Pair(core.network().paired, core.invitation()) }) { result ->
            result.onSuccess { (paired, invitation) ->
                renderDevices(paired)
                render(invitation)
            }.onFailure(::showError)
        }
    }

    override fun onEvent(event: CoreEvent) {
        if (event is CoreEvent.ShareChanged || event is CoreEvent.NetworkChanged) refresh() else super.onEvent(event)
    }

    private fun renderDevices(paired: List<PeerView>) {
        val list = find<LinearLayout>(R.id.share_devices)
        list.removeAllViews()
        for (peer in paired) {
            list.addView(
                Button(activity).apply {
                    text = activity.getString(R.string.this_device_format, peer.device.name, peer.device.fingerprint)
                    setOnClickListener { invite(peer.device.id) }
                },
            )
        }
    }

    private fun invite(recipient: String) {
        clearError()
        executor.run({ core.createInvitation(wallet, recipient) }) { result ->
            result.onSuccess { render(it) }.onFailure(::showError)
        }
    }

    private fun render(view: InvitationView?) {
        find<TextView>(R.id.invite_code).text = view?.code ?: ""
        find<TextView>(R.id.invite_state).text = view?.state?.name ?: ""
        find<TextView>(R.id.invite_recipient).text = view?.let {
            activity.getString(R.string.this_device_format, it.recipient.name, it.recipient.fingerprint)
        } ?: ""
        find<View>(R.id.accept_recipient_button).visibility =
            if (view?.state == InvitationState.AWAITING_ACCEPTANCE) View.VISIBLE else View.GONE
    }

    private fun confirmRecipient() {
        executor.run({ core.invitation() }) { result ->
            val view = result.getOrNull() ?: return@run
            SecureDialogs.confirm(activity, R.string.share_confirm_title, R.string.share_confirm, R.string.accept_recipient) {
                executor.run({ core.acceptRecipient(view.recipient.id) }) { done ->
                    done.onSuccess { refresh() }.onFailure(::showError)
                }
            }
        }
    }
}

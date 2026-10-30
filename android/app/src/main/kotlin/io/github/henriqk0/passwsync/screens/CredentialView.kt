package io.github.henriqk0.passwsync.screens

import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.SecureDialogs
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.CopyField
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.CredentialDetails
import io.github.henriqk0.passwsync.core.RevealTicket

/**
 * One credential. The password is shown only after "Reveal", through Secrets.platformText
 * (FR-009 amendment), and hidden again at the timeout, on lock and when the view is left
 * (FR-024). Copies go to the sensitive clipboard with a countdown (FR-021, FR-022).
 */
class CredentialView(
    activity: MainActivity,
    private val wallet: String,
    private val id: String,
) : Screen(activity, R.layout.credential_view) {
    private val main = Handler(Looper.getMainLooper())
    private val hide = Runnable { hidePassword() }
    private lateinit var countdown: Countdown
    private var revealed = false

    override fun bind() {
        countdown = Countdown(core, executor, find(R.id.countdown))
        find<Button>(R.id.reveal_button).setOnClickListener { if (revealed) leaveReveal() else reveal() }
        find<Button>(R.id.copy_username_button).setOnClickListener { copy(CopyField.USERNAME) }
        find<Button>(R.id.copy_password_button).setOnClickListener { copy(CopyField.PASSWORD) }
        find<Button>(R.id.edit_button).setOnClickListener { activity.show(CredentialEdit(activity, wallet, id)) }
        find<Button>(R.id.delete_button).setOnClickListener {
            SecureDialogs.confirm(activity, R.string.delete_confirm_title, R.string.delete_confirm, R.string.delete) {
                executor.run({ core.deleteCredential(wallet, id) }) { result ->
                    result.onSuccess { activity.back() }.onFailure(::showError)
                }
            }
        }
    }

    override fun refresh() {
        executor.run({ core.getCredential(wallet, id) }) { result ->
            result.onSuccess(::render).onFailure(::showError)
        }
    }

    private fun render(details: CredentialDetails) {
        clearError()
        find<TextView>(R.id.view_title).text = details.title
        find<TextView>(R.id.view_username).text = details.username
        find<TextView>(R.id.view_url).text = details.url
        find<TextView>(R.id.view_notes).text = details.notes
        find<View>(R.id.conflicted).visibility = View.GONE
    }

    private fun reveal() {
        executor.run({ core.revealPassword(wallet, id) }) { result ->
            result.onSuccess(::show).onFailure(::showError)
        }
    }

    private fun show(ticket: RevealTicket) {
        Secrets.use(ticket.password) {
            find<TextView>(R.id.revealed_password).text = Secrets.platformText(ticket.password)
        }
        revealed = true
        find<Button>(R.id.reveal_button).setText(R.string.hide)
        main.removeCallbacks(hide)
        main.postDelayed(hide, ticket.hideInMs.toLong())
    }

    private fun hidePassword() {
        main.removeCallbacks(hide)
        revealed = false
        find<TextView>(R.id.revealed_password).setText(R.string.hidden_password)
        find<Button>(R.id.reveal_button).setText(R.string.reveal)
    }

    private fun leaveReveal() {
        hidePassword()
        executor.run({ core.leaveCredentialView() })
    }

    private fun copy(field: CopyField) {
        executor.run({ core.copyField(wallet, id, field) }) { result ->
            result.onSuccess { countdown.start() }.onFailure(::showError)
        }
    }

    override fun onEvent(event: CoreEvent) {
        when (event) {
            is CoreEvent.RevealExpired -> hidePassword()
            is CoreEvent.ClipboardCleared -> countdown.stop()
            is CoreEvent.Locked -> if (event.name == wallet) {
                hidePassword()
                activity.home()
            }
            is CoreEvent.AllLocked -> {
                hidePassword()
                activity.home()
            }
            else -> Unit
        }
    }

    override fun leave() {
        countdown.stop()
        leaveReveal()
    }
}

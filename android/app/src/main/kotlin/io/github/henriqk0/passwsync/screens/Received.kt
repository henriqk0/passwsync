package io.github.henriqk0.passwsync.screens

import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.SecureDialogs
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.ReceivedView

/**
 * Received wallets not opened yet (ciphertext, deleted after 24 h; FR-052): open one with its
 * master password under a local name, or discard it.
 */
class Received(activity: MainActivity) : Screen(activity, R.layout.received) {
    private var selected: String? = null

    override fun bind() {
        find<Button>(R.id.open_received_button).setOnClickListener { open() }
        find<Button>(R.id.discard_received_button).setOnClickListener {
            val id = selected ?: return@setOnClickListener
            SecureDialogs.confirm(activity, R.string.discard_confirm_title, R.string.discard_confirm, R.string.discard_received) {
                executor.run({ core.discardReceived(id) }) { result -> result.onSuccess { refresh() }.onFailure(::showError) }
            }
        }
    }

    override fun refresh() {
        executor.run({ core.received() }) { result -> result.onSuccess(::render).onFailure(::showError) }
    }

    override fun onEvent(event: CoreEvent) {
        if (event is CoreEvent.ShareChanged || event is CoreEvent.ReceivedExpired) refresh() else super.onEvent(event)
    }

    override fun leave() {
        find<EditText>(R.id.received_password).text.clear()
    }

    private fun render(list: List<ReceivedView>) {
        find<View>(R.id.received_empty).visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
        val view = find<LinearLayout>(R.id.received_list)
        view.removeAllViews()
        for (item in list) {
            view.addView(
                Button(activity).apply {
                    text = activity.getString(R.string.this_device_format, item.from.name, item.from.fingerprint)
                    setOnClickListener { selected = item.id }
                },
            )
        }
    }

    private fun open() {
        clearError()
        val id = selected ?: return
        val name = Secrets.plain(find<EditText>(R.id.received_local_name)).trim()
        val password = Secrets.take(find<EditText>(R.id.received_password))
        executor.run({ Secrets.use(password) { core.openReceived(id, name, password) } }) { result ->
            result.onSuccess { activity.home() }.onFailure(::showError)
        }
    }
}

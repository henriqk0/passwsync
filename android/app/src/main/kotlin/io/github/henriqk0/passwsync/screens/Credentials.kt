package io.github.henriqk0.passwsync.screens

import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.CredentialSummary

/** The credentials of an unlocked wallet with search; lists never hold a password (FR-010). */
class Credentials(activity: MainActivity, private val wallet: String) : Screen(activity, R.layout.credentials) {
    private lateinit var countdown: Countdown

    override fun bind() {
        find<TextView>(R.id.credentials_wallet_name).text = wallet
        countdown = Countdown(core, executor, find(R.id.countdown))
        find<EditText>(R.id.search_query).addTextChangedListener(
            object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit

                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit

                override fun afterTextChanged(s: Editable?) = refresh()
            },
        )
        find<Button>(R.id.add_button).setOnClickListener { activity.show(CredentialEdit(activity, wallet, null)) }
        find<Button>(R.id.share_button).setOnClickListener { activity.show(Share(activity, wallet)) }
        find<Button>(R.id.change_password_button).setOnClickListener {
            activity.show(ChangePassword(activity, wallet))
        }
        find<Button>(R.id.lock_button).setOnClickListener {
            executor.run({ core.lockWallet(wallet) }) { activity.home() }
        }
    }

    override fun refresh() {
        val query = Secrets.plain(find<EditText>(R.id.search_query))
        executor.run({ core.search(wallet, query) }) { result ->
            result.onSuccess(::render).onFailure(::showError)
        }
        countdown.start()
    }

    override fun onEvent(event: CoreEvent) {
        when (event) {
            is CoreEvent.Locked -> if (event.name == wallet) activity.home()
            is CoreEvent.AllLocked -> activity.home()
            is CoreEvent.ClipboardCleared -> countdown.stop()
            else -> Unit
        }
    }

    override fun leave() {
        countdown.stop()
    }

    private fun render(found: List<CredentialSummary>) {
        clearError()
        val list = find<LinearLayout>(R.id.credentials)
        list.removeAllViews()
        find<View>(R.id.empty).visibility = if (found.isEmpty()) View.VISIBLE else View.GONE
        for (entry in found) {
            list.addView(
                Button(activity).apply {
                    text = if (entry.username.isEmpty()) entry.title else "${entry.title} — ${entry.username}"
                    setOnClickListener { activity.show(CredentialView(activity, wallet, entry.id)) }
                },
            )
        }
    }
}

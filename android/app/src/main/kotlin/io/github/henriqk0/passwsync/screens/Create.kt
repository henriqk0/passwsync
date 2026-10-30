package io.github.henriqk0.passwsync.screens

import android.widget.Button
import android.widget.EditText
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.Secrets

/**
 * A new wallet: name and the master password twice (FR-013). The checks (12 characters, the
 * two entries match, protections present) are the core's; this screen only executes them.
 */
class Create(activity: MainActivity) : Screen(activity, R.layout.create) {
    override fun bind() {
        find<Button>(R.id.create_button).setOnClickListener { create() }
    }

    private fun create() {
        clearError()
        val name = Secrets.plain(find<EditText>(R.id.wallet_name))
        val password = Secrets.take(find<EditText>(R.id.new_password))
        val confirm = Secrets.take(find<EditText>(R.id.confirm_password))
        find<Button>(R.id.create_button).isEnabled = false
        executor.run({
            Secrets.use(password, confirm) {
                core.createWallet(name, password, confirm)
            }
        }) { result ->
            find<Button>(R.id.create_button).isEnabled = true
            result.onSuccess { activity.replace(Credentials(activity, name)) }.onFailure(::showError)
        }
    }

    override fun leave() {
        Secrets.take(find<EditText>(R.id.new_password)).fill(0)
        Secrets.take(find<EditText>(R.id.confirm_password)).fill(0)
    }
}

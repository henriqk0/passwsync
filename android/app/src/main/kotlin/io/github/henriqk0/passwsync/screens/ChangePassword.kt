package io.github.henriqk0.passwsync.screens

import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.Secrets

/** Replaces the master password of an unlocked wallet; the current one is required (FR-019). */
class ChangePassword(activity: MainActivity, private val wallet: String) :
    Screen(activity, R.layout.change_password) {
    override fun bind() {
        find<TextView>(R.id.change_wallet_name).text = wallet
        find<Button>(R.id.change_button).setOnClickListener { change() }
    }

    private fun change() {
        clearError()
        val current = Secrets.take(find<EditText>(R.id.current_password))
        val next = Secrets.take(find<EditText>(R.id.new_password))
        val confirm = Secrets.take(find<EditText>(R.id.confirm_password))
        executor.run({
            Secrets.use(current, next, confirm) {
                core.changePassword(wallet, current, next, confirm)
            }
        }) { result ->
            result.onSuccess {
                find<TextView>(R.id.error).setText(R.string.password_changed)
            }.onFailure(::showError)
        }
    }

    override fun leave() {
        for (id in listOf(R.id.current_password, R.id.new_password, R.id.confirm_password)) {
            Secrets.take(find<EditText>(id)).fill(0)
        }
    }
}

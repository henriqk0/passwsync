package io.github.henriqk0.passwsync.screens

import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.Secrets

/** Unlocks one wallet; a wrong password and a damaged file show the same message (FR-014). */
class Unlock(activity: MainActivity, private val wallet: String) : Screen(activity, R.layout.unlock) {
    override fun bind() {
        find<TextView>(R.id.unlock_wallet_name).text = wallet
        find<Button>(R.id.unlock_button).setOnClickListener { unlock() }
    }

    private fun unlock() {
        clearError()
        val password = Secrets.take(find<EditText>(R.id.master_password))
        val button = find<Button>(R.id.unlock_button)
        val progress = find<TextView>(R.id.progress)
        button.isEnabled = false
        progress.setText(R.string.unlocking)
        executor.run({
            Secrets.use(password) {
                core.unlockWallet(wallet, password)
            }
        }) { result ->
            button.isEnabled = true
            progress.text = ""
            result.onSuccess { activity.replace(Credentials(activity, wallet)) }.onFailure(::showError)
        }
    }

    override fun leave() {
        Secrets.take(find<EditText>(R.id.master_password)).fill(0)
    }
}

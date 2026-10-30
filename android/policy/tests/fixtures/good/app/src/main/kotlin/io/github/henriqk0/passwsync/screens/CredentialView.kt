package io.github.henriqk0.passwsync.screens

import android.widget.TextView
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.PasswsyncCore

/** Shows one credential; the password only while revealed (FR-024). */
class CredentialView(private val core: PasswsyncCore, private val field: TextView) {
    fun reveal(wallet: String, id: String) {
        val ticket = core.revealPassword(wallet, id)
        Secrets.use(ticket.password) {
            field.text = Secrets.platformText(ticket.password)
        }
    }

    fun unlock(wallet: String, password: ByteArray) {
        Secrets.use(password) {
            core.unlockWallet(wallet, password)
        }
    }
}

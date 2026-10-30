package io.github.henriqk0.passwsync.screens

import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.CredentialInput

/**
 * Adds (`id == null`) or edits a credential. An empty password field on edit keeps the stored
 * password, which never travels to this screen (FR-010, FR-020).
 */
class CredentialEdit(
    activity: MainActivity,
    private val wallet: String,
    private val id: String?,
) : Screen(activity, R.layout.credential_edit) {
    override fun bind() {
        find<TextView>(R.id.edit_title).setText(if (id == null) R.string.new_credential_title else R.string.edit_title)
        find<Button>(R.id.save_button).setOnClickListener { save() }
        val existing = id ?: return
        executor.run({ core.getCredential(wallet, existing) }) { result ->
            result.onSuccess { details ->
                find<EditText>(R.id.credential_title).setText(details.title)
                find<EditText>(R.id.credential_username).setText(details.username)
                find<EditText>(R.id.credential_url).setText(details.url)
                find<EditText>(R.id.credential_notes).setText(details.notes)
            }.onFailure(::showError)
        }
    }

    private fun save() {
        clearError()
        val field = find<EditText>(R.id.credential_password)
        val typed = field.length() > 0
        val password = Secrets.take(field)
        val input = CredentialInput(
            title = Secrets.plain(find<EditText>(R.id.credential_title)),
            username = Secrets.plain(find<EditText>(R.id.credential_username)),
            url = Secrets.plain(find<EditText>(R.id.credential_url)),
            notes = Secrets.plain(find<EditText>(R.id.credential_notes)),
            password = if (typed) password else null,
        )
        val existing = id
        executor.run({
            Secrets.use(password) {
                if (existing == null) {
                    core.addCredential(wallet, input)
                } else {
                    core.updateCredential(wallet, existing, input)
                }
            }
        }) { result ->
            result.onSuccess { activity.back() }.onFailure(::showError)
        }
    }

    override fun onEvent(event: CoreEvent) {
        when (event) {
            is CoreEvent.Locked -> if (event.name == wallet) activity.home()
            is CoreEvent.AllLocked -> activity.home()
            else -> Unit
        }
    }

    override fun leave() {
        Secrets.take(find<EditText>(R.id.credential_password)).fill(0)
    }
}

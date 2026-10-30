package io.github.henriqk0.passwsync.screens

import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.core.ConflictChoice
import io.github.henriqk0.passwsync.core.ConflictVersionView
import io.github.henriqk0.passwsync.core.ConflictView
import io.github.henriqk0.passwsync.core.CopyField

/**
 * Conflicted credentials of an unlocked wallet and their versions (004, FR-049): keep one
 * version or keep both; a version's username or password is copied with the 002 clipboard
 * rules (sensitive, cleared after the timeout). No view carries a password.
 */
class Conflicts(activity: MainActivity, private val wallet: String) : Screen(activity, R.layout.conflicts) {
    private var selected: String? = null

    override fun bind() {
        find<TextView>(R.id.conflicts_wallet).text = wallet
        find<Button>(R.id.keep_both_button).setOnClickListener {
            val id = selected ?: return@setOnClickListener
            resolve(id, ConflictChoice.Both)
        }
    }

    override fun refresh() {
        executor.run({ core.conflicts(wallet) }) { result -> result.onSuccess(::render).onFailure(::showError) }
    }

    private fun render(list: List<ConflictView>) {
        clearError()
        val view = find<LinearLayout>(R.id.conflicts_list)
        view.removeAllViews()
        find<LinearLayout>(R.id.versions_list).removeAllViews()
        for (conflict in list) {
            view.addView(
                Button(activity).apply {
                    text = activity.getString(R.string.conflict_format, conflict.title, conflict.versions.toInt())
                    setOnClickListener { open(conflict.id) }
                },
            )
        }
    }

    private fun open(id: String) {
        selected = id
        executor.run({ core.conflictVersions(wallet, id) }) { result ->
            result.onSuccess { renderVersions(id, it) }.onFailure(::showError)
        }
    }

    private fun renderVersions(id: String, versions: List<ConflictVersionView>) {
        val list = find<LinearLayout>(R.id.versions_list)
        list.removeAllViews()
        for (version in versions) {
            list.addView(
                TextView(activity).apply {
                    text = activity.getString(R.string.version_format, version.title, version.username, version.device)
                },
            )
            list.addView(
                Button(activity).apply {
                    setText(R.string.copy_password)
                    setOnClickListener { copy(id, version.index, CopyField.PASSWORD) }
                },
            )
            list.addView(
                Button(activity).apply {
                    setText(R.string.keep_this_version)
                    setOnClickListener { resolve(id, ConflictChoice.Keep(version.index)) }
                },
            )
        }
    }

    private fun copy(id: String, index: UInt, field: CopyField) {
        executor.run({ core.copyConflictField(wallet, id, index, field) }) { result -> result.onFailure(::showError) }
    }

    private fun resolve(id: String, choice: ConflictChoice) {
        executor.run({ core.resolveConflict(wallet, id, choice) }) { result ->
            result.onSuccess { refresh() }.onFailure(::showError)
        }
    }
}

package io.github.henriqk0.passwsync.screens

import android.view.View
import android.widget.Button
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.core.MemoryLockLevel

/** The protection level reached at start, shown on every launch (FR-008, SC-012). */
class Security(activity: MainActivity) : Screen(activity, R.layout.security) {
    override fun bind() {
        find<Button>(R.id.back_button).setOnClickListener { activity.back() }
    }

    override fun refresh() {
        val status = core.protectionStatus()
        find<TextView>(R.id.core_dumps_value).setText(if (status.coreDumpsDisabled) R.string.yes else R.string.no)
        find<TextView>(R.id.non_dumpable_value).setText(if (status.nonDumpable) R.string.yes else R.string.no)
        find<TextView>(R.id.memory_lock_value).setText(
            when (status.memoryLock) {
                MemoryLockLevel.FULL -> R.string.memory_full
                MemoryLockLevel.SECRETS_ONLY -> R.string.memory_secrets_only
                MemoryLockLevel.NONE -> R.string.memory_none
            },
        )
        find<View>(R.id.missing_notice).visibility = if (status.canUnlock) View.GONE else View.VISIBLE
    }

    companion object {
        /** A short line for the wallet list header: the level is visible on every launch. */
        fun summary(level: MemoryLockLevel): Int = when (level) {
            MemoryLockLevel.FULL -> R.string.memory_full
            MemoryLockLevel.SECRETS_ONLY -> R.string.memory_secrets_only
            MemoryLockLevel.NONE -> R.string.memory_none
        }
    }
}

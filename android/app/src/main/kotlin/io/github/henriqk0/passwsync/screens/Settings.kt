package io.github.henriqk0.passwsync.screens

import android.view.View
import android.widget.Button
import android.widget.EditText
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.SecureDialogs
import io.github.henriqk0.passwsync.Secrets
import io.github.henriqk0.passwsync.core.SettingsInput
import io.github.henriqk0.passwsync.core.SettingsView

/**
 * Idle timeout, clipboard timeout, sync interval and device name (FR-033). The core
 * validates and saves; values apply after "Restart now", which locks everything first.
 */
class Settings(activity: MainActivity) : Screen(activity, R.layout.settings) {
    override fun bind() {
        find<Button>(R.id.save_button).setOnClickListener { save() }
        find<Button>(R.id.restart_button).setOnClickListener {
            SecureDialogs.confirm(activity, R.string.restart_confirm_title, R.string.restart_confirm, R.string.restart_now) {
                executor.run({ core.shutdown() }) { restartProcess() }
            }
        }
    }

    override fun refresh() {
        executor.run({ core.settings() }) { result -> result.onSuccess(::render).onFailure(::showError) }
    }

    private fun render(view: SettingsView) {
        find<EditText>(R.id.auto_lock_minutes).setText(view.autoLockMinutes.toString())
        find<EditText>(R.id.clipboard_clear_seconds).setText(view.clipboardClearSeconds.toString())
        find<EditText>(R.id.sync_interval_minutes).setText(view.syncIntervalMinutes.toString())
        find<EditText>(R.id.device_name).setText(view.deviceName)
        find<View>(R.id.reset_notice).visibility = if (view.resetNotice) View.VISIBLE else View.GONE
        find<View>(R.id.restart_notice).visibility = if (view.restartRequired) View.VISIBLE else View.GONE
    }

    private fun number(id: Int): UInt = Secrets.plain(find<EditText>(id)).trim().toUIntOrNull() ?: 0u

    private fun save() {
        clearError()
        val name = Secrets.plain(find<EditText>(R.id.device_name)).trim()
        val input = SettingsInput(
            autoLockMinutes = number(R.id.auto_lock_minutes),
            clipboardClearSeconds = number(R.id.clipboard_clear_seconds),
            deviceName = name.ifEmpty { null },
            syncIntervalMinutes = number(R.id.sync_interval_minutes),
            networkInterface = null,
        )
        executor.run({ core.updateSettings(input) }) { result ->
            result.onSuccess { refresh() }.onFailure(::showError)
        }
    }

    /** The core is started once per process: a restart is a new process. */
    private fun restartProcess() {
        val launch = activity.packageManager.getLaunchIntentForPackage(activity.packageName) ?: return
        activity.finishAffinity()
        activity.startActivity(launch)
        Runtime.getRuntime().exit(0)
    }
}

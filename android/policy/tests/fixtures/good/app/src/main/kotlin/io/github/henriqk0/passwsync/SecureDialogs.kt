package io.github.henriqk0.passwsync

import android.app.AlertDialog
import android.content.Context
import android.view.WindowManager

/** The only place dialogs are created; each window is FLAG_SECURE. */
object SecureDialogs {
    fun confirm(context: Context, message: Int, onYes: () -> Unit) {
        val dialog = AlertDialog.Builder(context)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok) { _, _ -> onYes() }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
    }
}

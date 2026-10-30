package io.github.henriqk0.passwsync

import android.app.AlertDialog
import android.content.Context
import android.view.WindowManager

/**
 * The only place dialogs are created (S2; FR-026). Every dialog window is FLAG_SECURE before
 * it is shown. No toast or snackbar exists in the app: messages are shown inline.
 */
object SecureDialogs {
    /** A yes/no confirmation; `onYes` runs on the main thread. */
    fun confirm(context: Context, title: Int, message: Int, yes: Int, onYes: () -> Unit) {
        val dialog = AlertDialog.Builder(context)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton(yes) { _, _ -> onYes() }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
    }

    /** A message with one button. */
    fun inform(context: Context, title: Int, message: Int) {
        val dialog = AlertDialog.Builder(context)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok, null)
            .create()
        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
    }
}

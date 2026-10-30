package io.github.henriqk0.passwsync

import android.os.Bundle
import android.widget.FrameLayout
import android.widget.TextView
import android.window.OnBackInvokedDispatcher
import io.github.henriqk0.passwsync.core.PasswsyncCore
import io.github.henriqk0.passwsync.screens.Screen
import io.github.henriqk0.passwsync.screens.WalletList

/**
 * The single activity (M6): screens are views swapped inside one FLAG_SECURE window; there is
 * no second activity and no fragment.
 */
class MainActivity : SecureActivity() {
    private lateinit var host: FrameLayout
    private val stack = ArrayDeque<Screen>()

    val app: PasswsyncApp
        get() = application as PasswsyncApp

    /** Present whenever a screen exists (MainActivity shows a notice otherwise). */
    val core: PasswsyncCore
        get() = checkNotNull(app.core)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        host = FrameLayout(this)
        setContentView(host)
        if (app.core == null) {
            host.addView(TextView(this).apply { setText(R.string.start_failed) })
            return
        }
        app.ui.listener = { event -> stack.lastOrNull()?.onEvent(event) }
        onBackInvokedDispatcher.registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT) { back() }
        show(WalletList(this))
    }

    override fun onStop() {
        // Leaving the app hides every revealed password (FR-024).
        stack.lastOrNull()?.leave()
        super.onStop()
    }

    override fun onStart() {
        super.onStart()
        stack.lastOrNull()?.refresh()
    }

    override fun onDestroy() {
        app.ui.listener = null
        super.onDestroy()
    }

    /** Shows `screen` on top of the current one. */
    fun show(screen: Screen) {
        stack.lastOrNull()?.leave()
        stack.addLast(screen)
        render()
    }

    /** Replaces the current screen (no way back to it). */
    fun replace(screen: Screen) {
        stack.removeLastOrNull()?.leave()
        stack.addLast(screen)
        render()
    }

    /** Back to the wallet list, dropping every screen above it (after a lock). */
    fun home() {
        while (stack.size > 1) stack.removeLast().leave()
        render()
    }

    fun back() {
        if (stack.size <= 1) {
            finish()
            return
        }
        stack.removeLast().leave()
        render()
    }

    private fun render() {
        host.removeAllViews()
        val screen = stack.last()
        host.addView(screen.attach(host))
        screen.refresh()
    }
}

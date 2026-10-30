package io.github.henriqk0.passwsync.screens

import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import io.github.henriqk0.passwsync.CoreExecutor
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.PasswsyncCore

/** One screen: a layout inflated into the activity, wired to the core. */
abstract class Screen(protected val activity: MainActivity, private val layout: Int) {
    protected lateinit var root: View
        private set

    protected val core: PasswsyncCore
        get() = activity.core

    protected val executor: CoreExecutor
        get() = activity.app.executor

    fun attach(parent: ViewGroup): View {
        root = activity.layoutInflater.inflate(layout, parent, false)
        bind()
        return root
    }

    /** Wires the views once after inflation. */
    protected abstract fun bind()

    /** Re-reads what the screen shows (on show and on return to the foreground). */
    open fun refresh() = Unit

    /** A core event arrived (main thread). */
    open fun onEvent(event: CoreEvent) {
        if (event is CoreEvent.AllLocked) activity.home()
    }

    /** The screen is no longer shown. */
    open fun leave() = Unit

    protected fun <T : View> find(id: Int): T = root.findViewById(id)

    /** The core's fixed English message (no user data, ffi-api.md section 4). */
    protected fun showError(error: Throwable) {
        find<TextView>(R.id.error).text = error.message
    }

    protected fun clearError() {
        find<TextView>(R.id.error).text = ""
    }
}

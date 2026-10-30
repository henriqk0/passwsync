package io.github.henriqk0.passwsync.screens

import android.os.Handler
import android.os.Looper
import android.widget.TextView
import io.github.henriqk0.passwsync.CoreExecutor
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.core.PasswsyncCore

/** Shows the clipboard countdown from `clipboardPendingMs` once per second (FR-022). */
class Countdown(
    private val core: PasswsyncCore,
    private val executor: CoreExecutor,
    private val view: TextView,
) {
    private val main = Handler(Looper.getMainLooper())
    private var running = false
    private val tick = object : Runnable {
        override fun run() {
            if (!running) return
            executor.run({ core.clipboardPendingMs() }) { result ->
                val left = result.getOrNull()
                if (left == null) {
                    view.text = ""
                    running = false
                } else {
                    val seconds = ((left.toLong() + 999L) / 1000L).toInt()
                    view.text = view.context.getString(R.string.clipboard_countdown, seconds)
                    main.postDelayed(this, 1_000L)
                }
            }
        }
    }

    fun start() {
        if (running) return
        running = true
        main.post(tick)
    }

    fun stop() {
        running = false
        main.removeCallbacks(tick)
        view.text = ""
    }
}

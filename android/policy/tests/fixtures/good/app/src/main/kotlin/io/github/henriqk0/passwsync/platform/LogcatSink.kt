package io.github.henriqk0.passwsync.platform

import android.util.Log
import io.github.henriqk0.passwsync.core.LogSink

/** The LogSink port: closed-set lines from the core, info level only (FR-057). */
class LogcatSink : LogSink {
    override fun line(text: String) {
        val line = text
        Log.i(TAG, line)
    }

    private companion object {
        const val TAG = "passwsync"
    }
}

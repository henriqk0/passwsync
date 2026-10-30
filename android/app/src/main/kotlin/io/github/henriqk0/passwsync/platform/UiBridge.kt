package io.github.henriqk0.passwsync.platform

import android.os.Handler
import android.os.Looper
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.UiNotifier

/**
 * The UiNotifier port: called from any core thread; every event is posted to the main thread.
 * The listener must not call back into the core synchronously (ffi-api.md section 7).
 */
class UiBridge : UiNotifier {
    private val main = Handler(Looper.getMainLooper())

    @Volatile
    var listener: ((CoreEvent) -> Unit)? = null

    /** The process-level listener (multicast lock, job plan), called before the screen's. */
    @Volatile
    var appListener: ((CoreEvent) -> Unit)? = null

    override fun changed(event: CoreEvent) {
        main.post {
            appListener?.invoke(event)
            listener?.invoke(event)
        }
    }
}

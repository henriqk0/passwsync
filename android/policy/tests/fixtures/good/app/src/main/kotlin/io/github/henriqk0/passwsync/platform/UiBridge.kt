package io.github.henriqk0.passwsync.platform

import android.os.Handler
import android.os.Looper
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.UiNotifier

/** The UiNotifier port: posts every event to the main thread. */
class UiBridge : UiNotifier {
    private val main = Handler(Looper.getMainLooper())
    var listener: ((CoreEvent) -> Unit)? = null

    override fun changed(event: CoreEvent) {
        main.post { listener?.invoke(event) }
    }
}

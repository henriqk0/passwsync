package io.github.henriqk0.passwsync

import android.os.Handler
import android.os.Looper
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * One background thread for every blocking core call (key derivation, saves); results are
 * posted to the main thread. Calls are serialized, so the UI never races the core.
 */
class CoreExecutor {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "passwsync-core").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())

    fun <T> run(work: () -> T, done: (Result<T>) -> Unit = {}) {
        worker.execute {
            val result = runCatching(work)
            main.post { done(result) }
        }
    }
}

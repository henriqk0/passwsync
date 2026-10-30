package io.github.henriqk0.passwsync

import android.app.Activity
import android.app.Application
import android.os.Bundle
import io.github.henriqk0.passwsync.core.CoreConfig
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.CoreException
import io.github.henriqk0.passwsync.core.PasswsyncCore
import io.github.henriqk0.passwsync.platform.ClipboardAdapter
import io.github.henriqk0.passwsync.platform.JobPlanner
import io.github.henriqk0.passwsync.platform.KeystoreSealer
import io.github.henriqk0.passwsync.platform.LogcatSink
import io.github.henriqk0.passwsync.platform.MulticastLockHolder
import io.github.henriqk0.passwsync.platform.NetworkClassifier
import io.github.henriqk0.passwsync.platform.ScreenOffReceiver
import io.github.henriqk0.passwsync.platform.UiBridge

/**
 * The process: the core is started here and only here (S13; FR-011). Foreground and
 * background are counted over the started activities and reported to the core; the plan the
 * core returns is handed to JobScheduler unchanged.
 */
class PasswsyncApp : Application(), Application.ActivityLifecycleCallbacks {
    /** Null only when the private storage cannot be used (shown by MainActivity). */
    var core: PasswsyncCore? = null
        private set
    val executor = CoreExecutor()
    val ui = UiBridge()
    private lateinit var jobs: JobPlanner
    private lateinit var multicast: MulticastLockHolder
    private var started = 0

    override fun onCreate() {
        super.onCreate()
        jobs = JobPlanner(this)
        multicast = MulticastLockHolder(this)
        val config = CoreConfig(noBackupFilesDir.absolutePath, emptyList())
        val running = try {
            PasswsyncCore.start(config, KeystoreSealer(), ClipboardAdapter(this), LogcatSink(), ui)
        } catch (_: CoreException) {
            null
        }
        core = running
        if (running != null) {
            ScreenOffReceiver.register(this, running, executor)
            NetworkClassifier(this, running, executor) { syncMulticast(running) }.start()
            ui.appListener = { event -> if (event is CoreEvent.NetworkChanged) syncMulticast(running) }
            registerActivityLifecycleCallbacks(this)
            // Jobs are never persisted: plan again at every process start (FR-044).
            executor.run({ running.backgroundPlan() }) { result -> result.onSuccess(jobs::apply) }
        }
    }

    override fun onActivityStarted(activity: Activity) {
        val running = core ?: return
        started += 1
        if (started == 1) executor.run({ running.onForeground() }) { syncMulticast(running) }
    }

    override fun onActivityStopped(activity: Activity) {
        val running = core ?: return
        started -= 1
        if (started == 0) {
            executor.run({ running.onBackground() }) { result ->
                result.onSuccess(jobs::apply)
                syncMulticast(running)
            }
        }
    }

    /** Holds the multicast lock exactly while the node runs (S12). */
    fun syncMulticast(running: PasswsyncCore) {
        executor.run({ multicast.sync(running) })
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit

    override fun onActivityResumed(activity: Activity) = Unit

    override fun onActivityPaused(activity: Activity) = Unit

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

    override fun onActivityDestroyed(activity: Activity) = Unit
}

package io.github.henriqk0.passwsync.platform

import android.app.job.JobParameters
import android.app.job.JobService
import io.github.henriqk0.passwsync.PasswsyncApp

/**
 * Runs the planned jobs on the core executor (M9: not exported, BIND_JOB_SERVICE). Job 1 calls
 * `onDeadline`; jobs 2 and 3 call `runSyncWindow` on a thread of their own (at most 120 s, never unlocks a wallet). Each
 * plans the next jobs from the core's answer and reports `jobFinished`.
 */
class CoreJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val app = application as PasswsyncApp
        val core = app.core ?: return false
        if (params.jobId == JobPlanner.DEADLINE_JOB) {
            app.executor.run({ core.onDeadline() }) { result ->
                result.onSuccess { plan -> JobPlanner(this).apply(plan) }
                jobFinished(params, false)
            }
        } else {
            // Its own thread, not the core executor: a window may take up to 120 s and must
            // not delay onForeground, which ends it early.
            Thread({
                val plan = runCatching {
                    core.runSyncWindow()
                    core.backgroundPlan()
                }
                plan.onSuccess { JobPlanner(this).apply(it) }
                app.syncMulticast(core)
                jobFinished(params, false)
            }, "passwsync-window").start()
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = false
}

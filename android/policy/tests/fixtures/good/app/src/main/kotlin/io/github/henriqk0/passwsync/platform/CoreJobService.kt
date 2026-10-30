package io.github.henriqk0.passwsync.platform

import android.app.job.JobParameters
import android.app.job.JobService

/** Runs deadline and sync-window jobs on the core executor. */
class CoreJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean = false

    override fun onStopJob(params: JobParameters): Boolean = false
}

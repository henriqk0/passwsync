package io.github.henriqk0.passwsync.platform

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import io.github.henriqk0.passwsync.core.BackgroundPlan

/**
 * Maps a BackgroundPlan 1:1 to JobScheduler jobs (FR-044, FR-048); a job whose field is none
 * is cancelled. Job 1 (deadline) runs `onDeadline` for the idle lock, the clipboard and the
 * reveal deadlines, with no battery or network constraint. Jobs 2 (periodic window) and 3
 * (extra window after leaving the foreground with unsent changes) run `runSyncWindow` only on
 * a local Wi-Fi or Ethernet network without VPN and with the battery not low (S10). No job is
 * persisted or expedited; no alarm and no wake lock exist.
 */
class JobPlanner(context: Context) {
    private val scheduler: JobScheduler = context.getSystemService(JobScheduler::class.java)
    private val service = ComponentName(context, CoreJobService::class.java)

    fun apply(plan: BackgroundPlan) {
        val deadline = plan.deadlineInMs
        if (deadline == null) {
            scheduler.cancel(DEADLINE_JOB)
        } else {
            scheduler.schedule(
                JobInfo.Builder(DEADLINE_JOB, service)
                    .setMinimumLatency(deadline.toLong())
                    .setOverrideDeadline(deadline.toLong() + SLACK_MS)
                    .build(),
            )
        }
        val periodic = plan.periodicWindowMinutes
        if (periodic == null) {
            scheduler.cancel(PERIODIC_WINDOW_JOB)
        } else if (scheduler.getPendingJob(PERIODIC_WINDOW_JOB) == null) {
            scheduler.schedule(
                JobInfo.Builder(PERIODIC_WINDOW_JOB, service)
                    .setPeriodic(periodic.toLong() * MINUTE_MS)
                    .setRequiresBatteryNotLow(true)
                    .setRequiredNetwork(localNetwork())
                    .build(),
            )
        }
        if (!plan.extraWindow || periodic == null) {
            scheduler.cancel(EXTRA_WINDOW_JOB)
        } else {
            scheduler.schedule(
                JobInfo.Builder(EXTRA_WINDOW_JOB, service)
                    .setMinimumLatency(plan.keepNetworkMs.toLong())
                    .setRequiresBatteryNotLow(true)
                    .setRequiredNetwork(localNetwork())
                    .build(),
            )
        }
    }

    /** Wi-Fi or Ethernet, not a VPN, internet access not required (a LAN without uplink). */
    private fun localNetwork(): NetworkRequest =
        NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

    companion object {
        const val DEADLINE_JOB = 1
        const val PERIODIC_WINDOW_JOB = 2
        const val EXTRA_WINDOW_JOB = 3

        /** Allowed lateness of the deadline job (SC-007: cleared within timeout + 5 s). */
        private const val SLACK_MS = 5_000L
        private const val MINUTE_MS = 60_000L
    }
}

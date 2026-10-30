package io.github.henriqk0.passwsync.platform

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import io.github.henriqk0.passwsync.core.BackgroundPlan

/** Maps a BackgroundPlan 1:1 to JobScheduler jobs (FR-044, FR-048). */
class JobPlanner(private val context: Context) {
    private val scheduler = context.getSystemService(JobScheduler::class.java)
    private val service = ComponentName(context, CoreJobService::class.java)

    fun apply(plan: BackgroundPlan) {
        val deadline = plan.deadlineInMs
        if (deadline == null) scheduler.cancel(DEADLINE_JOB) else scheduler.schedule(
            JobInfo.Builder(DEADLINE_JOB, service)
                .setMinimumLatency(deadline.toLong())
                .build(),
        )
        val minutes = plan.periodicWindowMinutes
        if (minutes == null) scheduler.cancel(PERIODIC_JOB) else scheduler.schedule(
            JobInfo.Builder(PERIODIC_JOB, service)
                .setPeriodic(minutes.toLong() * 60_000L)
                .setRequiresBatteryNotLow(true)
                .setRequiredNetwork(localNetwork())
                .build(),
        )
        if (!plan.extraWindow) scheduler.cancel(EXTRA_JOB) else scheduler.schedule(
            JobInfo.Builder(EXTRA_JOB, service)
                .setRequiresBatteryNotLow(true)
                .setRequiredNetwork(localNetwork())
                .build(),
        )
    }

    private fun localNetwork(): NetworkRequest = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .build()

    private companion object {
        const val DEADLINE_JOB = 1
        const val PERIODIC_JOB = 2
        const val EXTRA_JOB = 3
    }
}

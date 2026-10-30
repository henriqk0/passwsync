package io.github.henriqk0.passwsync.platform

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build

/**
 * The local-network runtime permission of API 37 (M4). Requested only when the person
 * confirms switching networking on; never at start and never for any other reason.
 */
object LocalNetworkPermission {
    private const val PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
    private const val REQUEST = 37
    private const val API_LOCAL_NETWORK = 37

    fun needed(activity: Activity): Boolean =
        Build.VERSION.SDK_INT >= API_LOCAL_NETWORK &&
            activity.checkSelfPermission(PERMISSION) != PackageManager.PERMISSION_GRANTED

    /** Asks once after the switch-on confirmation; the switch is saved either way. */
    fun requestAfterConfirmation(activity: Activity) {
        if (needed(activity)) activity.requestPermissions(arrayOf(PERMISSION), REQUEST)
    }
}

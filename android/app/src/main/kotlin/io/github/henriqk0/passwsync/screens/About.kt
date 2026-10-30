package io.github.henriqk0.passwsync.screens

import android.widget.Button
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R

/**
 * What the person must know: uninstall or clear-data deletes wallets held only here; screen
 * readers can read visible content; no cloud backup.
 */
class About(activity: MainActivity) : Screen(activity, R.layout.about) {
    override fun bind() {
        find<Button>(R.id.back_button).setOnClickListener { activity.back() }
    }
}

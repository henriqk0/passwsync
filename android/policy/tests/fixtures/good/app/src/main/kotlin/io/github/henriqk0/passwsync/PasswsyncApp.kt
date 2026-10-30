package io.github.henriqk0.passwsync

import android.app.Application
import io.github.henriqk0.passwsync.core.CoreConfig
import io.github.henriqk0.passwsync.core.PasswsyncCore
import io.github.henriqk0.passwsync.platform.ClipboardAdapter
import io.github.henriqk0.passwsync.platform.KeystoreSealer
import io.github.henriqk0.passwsync.platform.LogcatSink
import io.github.henriqk0.passwsync.platform.ScreenOffReceiver
import io.github.henriqk0.passwsync.platform.UiBridge

class PasswsyncApp : Application() {
    lateinit var core: PasswsyncCore
        private set

    override fun onCreate() {
        super.onCreate()
        val config = CoreConfig(noBackupFilesDir.absolutePath, emptyList())
        core = PasswsyncCore.start(config, KeystoreSealer(), ClipboardAdapter(this), LogcatSink(), UiBridge())
        ScreenOffReceiver.register(this, core)
    }
}

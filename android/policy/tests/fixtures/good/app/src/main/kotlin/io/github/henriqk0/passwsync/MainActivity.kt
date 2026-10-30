package io.github.henriqk0.passwsync

import android.os.Bundle

class MainActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.screen_unlock)
    }
}

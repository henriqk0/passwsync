package io.github.henriqk0.passwsync.screens

import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.WalletInfo

/** Every wallet on the phone, locked or not (FR-013). Listing never counts as activity. */
class WalletList(activity: MainActivity) : Screen(activity, R.layout.wallet_list) {
    override fun bind() {
        find<Button>(R.id.create_button).setOnClickListener { activity.show(Create(activity)) }
        find<Button>(R.id.lock_all_button).setOnClickListener {
            executor.run({ core.lockAll() }) { refresh() }
        }
        find<Button>(R.id.network_button).setOnClickListener { activity.show(Network(activity)) }
        find<Button>(R.id.sync_status_button).setOnClickListener { activity.show(SyncStatus(activity)) }
        find<Button>(R.id.receive_button).setOnClickListener { activity.show(Receive(activity)) }
        find<Button>(R.id.received_button).setOnClickListener { activity.show(Received(activity)) }
        find<Button>(R.id.security_button).setOnClickListener { activity.show(Security(activity)) }
        find<Button>(R.id.settings_button).setOnClickListener { activity.show(Settings(activity)) }
        find<Button>(R.id.about_button).setOnClickListener { activity.show(About(activity)) }
    }

    override fun refresh() {
        // The protection level is visible on every launch (FR-008, SC-012).
        find<TextView>(R.id.protection_level).setText(Security.summary(core.protectionStatus().memoryLock))
        executor.run({ core.listWallets() }) { result ->
            result.onSuccess(::render).onFailure(::showError)
        }
    }

    override fun onEvent(event: CoreEvent) {
        refresh()
    }

    private fun render(wallets: List<WalletInfo>) {
        clearError()
        val list = find<LinearLayout>(R.id.wallets)
        list.removeAllViews()
        find<View>(R.id.empty).visibility = if (wallets.isEmpty()) View.VISIBLE else View.GONE
        for (wallet in wallets) {
            val label = if (wallet.unlocked) R.string.wallet_unlocked else R.string.wallet_locked
            list.addView(
                Button(activity).apply {
                    text = activity.getString(label, wallet.name)
                    setOnClickListener {
                        activity.show(
                            if (wallet.unlocked) Credentials(activity, wallet.name) else Unlock(activity, wallet.name),
                        )
                    }
                },
            )
        }
    }
}

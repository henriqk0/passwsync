package io.github.henriqk0.passwsync.screens

import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import io.github.henriqk0.passwsync.MainActivity
import io.github.henriqk0.passwsync.R
import io.github.henriqk0.passwsync.core.CoreEvent
import io.github.henriqk0.passwsync.core.SyncView
import io.github.henriqk0.passwsync.core.WalletSyncState

/** Sync state per wallet and per paired device; "Sync now" in the foreground (FR-049). */
class SyncStatus(activity: MainActivity) : Screen(activity, R.layout.sync_status) {
    override fun bind() {
        find<Button>(R.id.sync_now_button).setOnClickListener {
            executor.run({ core.syncNow() }) { result -> result.onSuccess { refresh() }.onFailure(::showError) }
        }
    }

    override fun refresh() {
        executor.run({ core.syncStatus() }) { result -> result.onSuccess(::render).onFailure(::showError) }
    }

    override fun onEvent(event: CoreEvent) {
        if (event is CoreEvent.SyncChanged || event is CoreEvent.WalletsChanged) refresh() else super.onEvent(event)
    }

    private fun render(view: SyncView) {
        clearError()
        find<TextView>(R.id.sync_running).text =
            if (view.running) activity.getString(R.string.sync_running) else ""
        val wallets = find<LinearLayout>(R.id.sync_wallets)
        wallets.removeAllViews()
        for (wallet in view.wallets) {
            wallets.addView(
                Button(activity).apply {
                    text = activity.getString(R.string.sync_wallet_format, wallet.wallet, stateWord(wallet.state))
                    setOnClickListener { activity.show(Conflicts(activity, wallet.wallet)) }
                },
            )
        }
        val peers = find<LinearLayout>(R.id.sync_peers)
        peers.removeAllViews()
        for (peer in view.peers) {
            peers.addView(
                TextView(activity).apply {
                    text = activity.getString(R.string.device_format, peer.device.name, peer.device.fingerprint, peer.state)
                },
            )
        }
    }

    private fun stateWord(state: WalletSyncState): String = when (state) {
        is WalletSyncState.SyncOff -> activity.getString(R.string.sync_state_off)
        is WalletSyncState.Disabled -> activity.getString(R.string.sync_state_disabled)
        is WalletSyncState.PossibleRollback -> activity.getString(R.string.sync_state_rollback)
        is WalletSyncState.Conflicts -> activity.getString(R.string.sync_state_conflicts, state.count.toInt())
        is WalletSyncState.ChangesWaiting -> activity.getString(R.string.sync_state_waiting)
        is WalletSyncState.Syncing -> activity.getString(R.string.sync_state_syncing)
        is WalletSyncState.SyncError -> activity.getString(R.string.sync_state_error)
        is WalletSyncState.NotSynced -> activity.getString(R.string.sync_state_not_synced)
        is WalletSyncState.InSync -> activity.getString(R.string.sync_state_in_sync)
    }
}

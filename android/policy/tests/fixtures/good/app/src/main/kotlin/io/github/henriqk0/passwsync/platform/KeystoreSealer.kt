package io.github.henriqk0.passwsync.platform

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.henriqk0.passwsync.core.KeySealer
import io.github.henriqk0.passwsync.core.PlatformException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The KeySealer port: AES-GCM under a non-exportable Keystore key, AAD = label. */
class KeystoreSealer : KeySealer {
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    override fun seal(label: String, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(label.toByteArray())
        return cipher.iv + cipher.doFinal(plaintext)
    }

    override fun open(label: String, sealed: ByteArray): ByteArray {
        if (sealed.size < 28) throw PlatformException.Failed()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed, 0, 12))
        cipher.updateAAD(label.toByteArray())
        return cipher.doFinal(sealed, 12, sealed.size - 12)
    }

    override fun reset() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(ALIAS)
    }

    private companion object {
        const val ALIAS = "passwsync-identity"
    }
}

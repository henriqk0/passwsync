package io.github.henriqk0.passwsync.platform

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.github.henriqk0.passwsync.core.KeySealer
import io.github.henriqk0.passwsync.core.PlatformException
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The KeySealer port (S15; FR-034, FR-035): AES-256-GCM under a non-exportable Keystore key
 * (StrongBox when the device has it), AAD = the label, random IV chosen by the Keystore. The
 * blob is `iv(12) || ciphertext || tag(16)`. Only the identity and the pins are ever sealed;
 * this class implements the port and nothing else.
 */
class KeystoreSealer : KeySealer {
    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun spec(strongBox: Boolean): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .build()

    private fun key(): SecretKey {
        (store().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            generator.init(spec(strongBox = true))
            generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            generator.init(spec(strongBox = false))
            generator.generateKey()
        }
    }

    override fun seal(label: String, plaintext: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(label.toByteArray(Charsets.UTF_8))
            val iv = cipher.iv
            if (iv.size != IV_BYTES) throw PlatformException.Failed()
            return iv + cipher.doFinal(plaintext)
        } catch (_: GeneralSecurityException) {
            throw PlatformException.Failed()
        } finally {
            plaintext.fill(0)
        }
    }

    override fun open(label: String, sealed: ByteArray): ByteArray {
        if (sealed.size < IV_BYTES + TAG_BYTES) throw PlatformException.Failed()
        val key = try {
            store().getKey(ALIAS, null) as? SecretKey
        } catch (_: GeneralSecurityException) {
            throw PlatformException.Unavailable()
        } ?: throw PlatformException.Invalidated()
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, sealed, 0, IV_BYTES))
            cipher.updateAAD(label.toByteArray(Charsets.UTF_8))
            return cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
        } catch (_: android.security.keystore.KeyPermanentlyInvalidatedException) {
            throw PlatformException.Invalidated()
        } catch (_: GeneralSecurityException) {
            throw PlatformException.Failed()
        }
    }

    override fun reset() {
        try {
            store().deleteEntry(ALIAS)
            key()
        } catch (_: GeneralSecurityException) {
            throw PlatformException.Failed()
        }
    }

    private companion object {
        const val ALIAS = "passwsync-identity"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
    }
}

package io.github.henriqk0.passwsync

import android.text.Editable
import android.widget.TextView
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * The only conversion site between platform text and bytes (S4; FR-009).
 *
 * Secrets leave an input field as a `ByteArray` (never a `String`), the field is overwritten
 * and cleared, and every secret array is zero-filled in `finally` by [use]. The reverse
 * direction, [platformText], exists only for the clipboard entry and the revealed password
 * (FR-009 amendment, research R7) and is called only from `platform/ClipboardAdapter.kt` and
 * `screens/CredentialView.kt`.
 */
object Secrets {
    /** UTF-8 bytes of a secret field; the field is overwritten and cleared. */
    fun take(field: Editable): ByteArray {
        val chars = CharArray(field.length)
        field.getChars(0, field.length, chars, 0)
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
        val buffer = encoder.encode(CharBuffer.wrap(chars))
        val out = ByteArray(buffer.remaining())
        buffer.get(out)
        if (buffer.hasArray()) buffer.array().fill(0)
        chars.fill('\u0000')
        for (i in 0 until field.length) field.replace(i, i + 1, "\u0000")
        field.clear()
        return out
    }

    /** UTF-8 bytes of the secret field of `view`. */
    fun take(view: TextView): ByteArray = take(view.editableText)

    /** A non-secret field (wallet name, title, username, URL, notes, search query). */
    fun plain(view: TextView): String = view.text.toString()

    /** Secret bytes as platform text, for the clipboard and the revealed password only. */
    fun platformText(bytes: ByteArray): CharSequence {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
        return decoder.decode(ByteBuffer.wrap(bytes))
    }

    /** Runs `block` and zero-fills every array afterwards, also on exceptions. */
    inline fun <T> use(vararg secrets: ByteArray, block: () -> T): T {
        try {
            return block()
        } finally {
            for (secret in secrets) secret.fill(0)
        }
    }
}

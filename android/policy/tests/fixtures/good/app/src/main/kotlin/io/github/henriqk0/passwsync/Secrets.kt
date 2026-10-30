package io.github.henriqk0.passwsync

import android.text.Editable
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets

/** The only conversion site between platform text and secret bytes (FR-009). */
object Secrets {
    fun bytes(text: Editable): ByteArray {
        val chars = CharArray(text.length)
        text.getChars(0, text.length, chars, 0)
        val buffer = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars))
        val out = ByteArray(buffer.remaining())
        buffer.get(out)
        chars.fill('\u0000')
        text.clear()
        return out
    }

    fun platformText(bytes: ByteArray): CharSequence = StandardCharsets.UTF_8.decode(java.nio.ByteBuffer.wrap(bytes))

    inline fun <T> use(vararg secrets: ByteArray, block: () -> T): T {
        try {
            return block()
        } finally {
            for (secret in secrets) secret.fill(0)
        }
    }
}

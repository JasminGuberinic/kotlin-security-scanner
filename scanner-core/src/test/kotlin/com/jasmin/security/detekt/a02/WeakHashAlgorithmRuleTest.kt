package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class WeakHashAlgorithmRuleTest {

    private val rule = WeakHashAlgorithmRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags MessageDigest getInstance MD5`() {
        val code = """
            import java.security.MessageDigest
            fun hash(data: ByteArray): ByteArray =
                MessageDigest.getInstance("MD5").digest(data)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags MessageDigest getInstance SHA-1`() {
        val code = """
            import java.security.MessageDigest
            fun hash(data: ByteArray): ByteArray =
                MessageDigest.getInstance("SHA-1").digest(data)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags MessageDigest getInstance SHA1 without hyphen`() {
        val code = """
            import java.security.MessageDigest
            fun hash(data: ByteArray): ByteArray =
                MessageDigest.getInstance("SHA1").digest(data)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores SHA-256`() {
        val code = """
            import java.security.MessageDigest
            fun hash(data: ByteArray): ByteArray =
                MessageDigest.getInstance("SHA-256").digest(data)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores SHA-512`() {
        val code = """
            import java.security.MessageDigest
            fun hash(data: ByteArray): ByteArray =
                MessageDigest.getInstance("SHA-512").digest(data)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores getInstance on other classes`() {
        val code = """
            import javax.crypto.Cipher
            fun encrypt(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on weak cipher fixture`() {
        val code = """
            import javax.crypto.Cipher
            fun legacyEncrypt(): Cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

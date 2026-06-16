package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class UnsafeCryptoPaddingOracleRuleTest {

    private val rule = UnsafeCryptoPaddingOracleRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags AES CBC PKCS5Padding`() {
        val code = """
            fun cipher(): Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags AES CBC PKCS5Padding in encryption helper`() {
        val code = """
            fun encrypt(key: SecretKey, data: ByteArray): ByteArray {
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.ENCRYPT_MODE, key)
                return cipher.doFinal(data)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags AES CBC PKCS5Padding stored in val`() {
        val code = """
            val cipherMode = "AES/CBC/PKCS5Padding"
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores AES GCM NoPadding`() {
        val code = """
            fun cipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores AES CBC with different padding`() {
        val code = """
            fun cipher(): Cipher = Cipher.getInstance("AES/CBC/NoPadding")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores MessageDigest getInstance`() {
        val code = """
            fun hasher() = MessageDigest.getInstance("SHA-256")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores getInstance with variable`() {
        val code = """
            fun cipher(mode: String): Cipher = Cipher.getInstance(mode)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on WeakCipherMode fixture`() {
        val code = """
            fun cipher(): Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecurePasswordStorageRuleTest {

    private val rule = InsecurePasswordStorageRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags MessageDigest SHA-256 inside hashPassword function`() {
        val code = """
            fun hashPassword(password: String): ByteArray {
                val digest = MessageDigest.getInstance("SHA-256")
                return digest.digest(password.toByteArray())
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags MessageDigest MD5 inside encodePassword function`() {
        val code = """
            fun encodePassword(pwd: String): String {
                return MessageDigest.getInstance("MD5")
                    .digest(pwd.toByteArray())
                    .joinToString("") { "%02x".format(it) }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags MessageDigest SHA-1 inside checkPassword function`() {
        val code = """
            fun checkPassword(passwd: String, stored: String): Boolean {
                val hash = MessageDigest.getInstance("SHA-1").digest(passwd.toByteArray())
                return hash.contentEquals(stored.toByteArray())
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags DigestUtils sha256Hex inside hashPassword`() {
        val code = """
            fun hashPassword(password: String): String = DigestUtils.sha256Hex(password)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags DigestUtils md5Hex inside encodeCredential`() {
        val code = """
            fun encodeCredential(pwd: String): String = DigestUtils.md5Hex(pwd)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores MessageDigest SHA-256 outside password function`() {
        val code = """
            fun generateChecksum(data: ByteArray): ByteArray {
                return MessageDigest.getInstance("SHA-256").digest(data)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores BCryptPasswordEncoder`() {
        val code = """
            fun hashPassword(password: String): String = BCryptPasswordEncoder().encode(password)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores DigestUtils sha256Hex outside password function`() {
        val code = """
            fun buildEtag(content: String): String = DigestUtils.sha256Hex(content)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on WeakHashAlgorithm fixture`() {
        val code = """
            fun computeFileHash(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

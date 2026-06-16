package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class WeakRsaKeyRuleTest {

    private val rule = WeakRsaKeyRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags initialize with 512-bit key`() {
        val code = """
            fun makeKey() {
                val kpg = KeyPairGenerator.getInstance("RSA")
                kpg.initialize(512)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags initialize with 1024-bit key`() {
        val code = """
            fun makeKey() {
                val kpg = KeyPairGenerator.getInstance("RSA")
                kpg.initialize(1024)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags initialize with 768-bit key`() {
        val code = """
            fun makeKey() = KeyPairGenerator.getInstance("RSA").also { it.initialize(768) }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores initialize with 2048-bit key`() {
        val code = """
            fun makeKey() {
                val kpg = KeyPairGenerator.getInstance("RSA")
                kpg.initialize(2048)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores initialize with 4096-bit key`() {
        val code = """
            fun makeKey() {
                val kpg = KeyPairGenerator.getInstance("RSA")
                kpg.initialize(4096)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores initialize with variable size`() {
        val code = """
            fun makeKey(size: Int) {
                val kpg = KeyPairGenerator.getInstance("RSA")
                kpg.initialize(size)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on HardcodedIv fixture`() {
        val code = """
            fun encrypt() {
                val iv = IvParameterSpec(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

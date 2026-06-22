package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecureRandomSeedRuleTest {

    private val rule = InsecureRandomSeedRule(Config.empty)

    @Test
    fun `flags SecureRandom constructor with byteArrayOf literal`() {
        val code = """
            import java.security.SecureRandom
            val rng = SecureRandom(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setSeed with numeric constant`() {
        val code = """
            import java.security.SecureRandom
            fun build(): SecureRandom {
                val rng = SecureRandom()
                rng.setSeed(12345L)
                return rng
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setSeed with byteArrayOf literals`() {
        val code = """
            import java.security.SecureRandom
            fun build(): SecureRandom {
                val rng = SecureRandom()
                rng.setSeed(byteArrayOf(0x01, 0x02, 0x03, 0x04))
                return rng
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores SecureRandom no-arg constructor`() {
        val code = """
            import java.security.SecureRandom
            val rng = SecureRandom()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores SecureRandom constructor with variable`() {
        val code = """
            import java.security.SecureRandom
            fun build(seedBytes: ByteArray) = SecureRandom(seedBytes)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores setSeed with variable`() {
        val code = """
            import java.security.SecureRandom
            fun build(seed: Long): SecureRandom {
                val rng = SecureRandom()
                rng.setSeed(seed)
                return rng
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

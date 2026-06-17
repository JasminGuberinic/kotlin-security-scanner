package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class WeakBcryptRoundsRuleTest {

    private val rule = WeakBcryptRoundsRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags BCryptPasswordEncoder with strength 4`() {
        val code = """
            fun encoder() = BCryptPasswordEncoder(4)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags BCryptPasswordEncoder with strength 8`() {
        val code = """
            fun encoder() = BCryptPasswordEncoder(8)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags BCryptPasswordEncoder with strength 1`() {
        val code = """
            fun encoder() = BCryptPasswordEncoder(1)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores BCryptPasswordEncoder with no argument`() {
        val code = """
            fun encoder() = BCryptPasswordEncoder()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores BCryptPasswordEncoder with strength 10`() {
        val code = """
            fun encoder() = BCryptPasswordEncoder(10)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores BCryptPasswordEncoder with strength 12`() {
        val code = """
            fun encoder() = BCryptPasswordEncoder(12)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on InsecurePasswordEncoder fixture`() {
        val code = """
            import org.springframework.security.crypto.password.NoOpPasswordEncoder
            fun encoder() = NoOpPasswordEncoder.getInstance()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

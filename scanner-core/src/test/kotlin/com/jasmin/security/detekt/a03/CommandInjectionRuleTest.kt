package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class CommandInjectionRuleTest {

    private val rule = CommandInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags Runtime exec with interpolated string`() {
        val code = """
            fun run(cmd: String) {
                Runtime.getRuntime().exec("ls ${'$'}cmd")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ProcessBuilder with variable argument`() {
        val code = """
            fun run(userInput: String) {
                ProcessBuilder(userInput)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ProcessBuilder with list containing variable`() {
        val code = """
            fun run(arg: String) {
                ProcessBuilder(listOf("sh", "-c", arg))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores exec with all-literal string`() {
        val code = """
            fun run() {
                Runtime.getRuntime().exec("ls -l /tmp")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores ProcessBuilder with only literals`() {
        val code = """
            fun run() {
                ProcessBuilder("ls", "-la")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on SQL injection fixture`() {
        val code = """
            fun find(name: String): List<User> {
                val q = "SELECT * FROM users WHERE name = ${'$'}name"
                return db.query(q)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

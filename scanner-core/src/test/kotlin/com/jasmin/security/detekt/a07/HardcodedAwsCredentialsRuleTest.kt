package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HardcodedAwsCredentialsRuleTest {

    private val rule = HardcodedAwsCredentialsRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags AKIA access key literal`() {
        val code = """
            val awsKey = "AKIAIOSFODNN7EXAMPLE"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ASIA temporary credentials key`() {
        val code = """
            val tempKey = "ASIAIOSFODNN7EXAMPLE"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags AROA role access key`() {
        val code = """
            val roleKey = "AROAIOSFODNN7EXAMPLE"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────="────────────────

    @Test
    fun `ignores key read from environment variable`() {
        val code = """
            val awsKey = System.getenv("AWS_ACCESS_KEY_ID")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores short AKIA-prefixed string`() {
        val code = """
            val name = "AKIA"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores lowercase akia string`() {
        val code = """
            val name = "akiaiosfodnn7example"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on HardcodedCredentials fixture`() {
        val code = """
            val password = "hunter2"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

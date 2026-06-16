package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class HardcodedCredentialsRuleTest {

    private val rule = HardcodedCredentialsRule()

    @Test
    fun `flags hardcoded password`() {
        val code = """val password = "supersecret123""""
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags hardcoded api key`() {
        val code = """val apiKey = "sk-prod-abc123xyz""""
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags hardcoded token`() {
        val code = """val authToken = "Bearer eyJhbGciOiJSUzI1NiJ9""""
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags hardcoded client secret`() {
        val code = """val clientSecret = "my-oauth-secret-value""""
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores spring property placeholder`() {
        val code = """val password = "${'$'}{app.db.password}""""
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores empty string`() {
        val code = """val password = """""
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores short value`() {
        val code = """val pwd = "ab""""
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores placeholder value`() {
        val code = """val password = "changeme""""
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-credential variable names`() {
        val code = """val username = "admin123""""
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag SQL injection patterns
    @Test
    fun `does not interfere with sql injection code`() {
        val code = """
            fun findUser(username: String): String {
                return "SELECT * FROM users WHERE username = '${'$'}username'"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a10

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class SsrfRuleTest {

    private val rule = SsrfRule()

    @Test
    fun `flags URL with variable argument`() {
        val code = """
            fun fetch(userUrl: String) = java.net.URL(userUrl)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags URL with string interpolation`() {
        val code = """
            fun fetch(host: String) = java.net.URL("https://${'$'}host/api")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags URI with variable argument`() {
        val code = """
            fun fetch(userUri: String) = java.net.URI(userUri)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores URL with string literal`() {
        val code = """
            val url = java.net.URL("https://api.example.com/data")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores URI with string literal`() {
        val code = """
            val uri = java.net.URI("https://api.example.com/data")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag path traversal patterns
    @Test
    fun `does not interfere with path traversal code`() {
        val code = """
            fun readFile(path: String) = java.io.File(path)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag hardcoded credential patterns
    @Test
    fun `does not interfere with hardcoded credential code`() {
        val code = """val apiSecret = "hardcoded-value""""
        assertThat(rule.lint(code)).isEmpty()
    }
}

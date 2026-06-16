package com.jasmin.security.detekt.a10

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class WebClientSSRFRuleTest {

    private val rule = WebClientSSRFRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags WebClient create with variable URL`() {
        val code = """
            fun fetch(url: String) = WebClient.create(url).get().retrieve().bodyToMono(String::class.java)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags WebClient create with request parameter`() {
        val code = """
            fun proxy(@RequestParam targetUrl: String) = WebClient.create(targetUrl)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags WebClient create with interpolated URL`() {
        val code = """
            fun fetch(host: String) = WebClient.create("http://${'$'}host/api")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores WebClient create with literal base URL`() {
        val code = """
            fun client() = WebClient.create("https://api.internal.example.com")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores create on non-WebClient receiver`() {
        val code = """
            fun builder() = HttpClient.create("https://host.internal")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on SpelInjection fixture`() {
        val code = """
            fun evaluate(expr: String) = SpelExpressionParser().parseExpression(expr).getValue()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

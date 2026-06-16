package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ResponseSplittingRuleTest {

    private val rule = ResponseSplittingRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags addHeader with variable value`() {
        val code = """
            fun setCustomHeader(response: HttpServletResponse, value: String) {
                response.addHeader("X-Custom", value)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setHeader with interpolated value`() {
        val code = """
            fun setLocation(response: HttpServletResponse, host: String) {
                response.setHeader("Location", "https://${'$'}host/callback")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags addHeader with method call result`() {
        val code = """
            fun forward(response: HttpServletResponse, req: HttpServletRequest) {
                response.addHeader("X-Forwarded-For", req.getHeader("X-Forwarded-For"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores setHeader with literal value`() {
        val code = """
            fun setNoCache(response: HttpServletResponse) {
                response.setHeader("Cache-Control", "no-store, no-cache")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores addHeader with literal value`() {
        val code = """
            fun setFrameOptions(response: HttpServletResponse) {
                response.addHeader("X-Frame-Options", "DENY")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores setHeader with only one argument`() {
        val code = """
            fun resetStatus(response: HttpServletResponse) {
                response.setHeader("Cache-Control")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on SpEL injection fixture`() {
        val code = """
            import org.springframework.expression.spel.standard.SpelExpressionParser
            fun eval(expr: String): Any? = SpelExpressionParser().parseExpression(expr).getValue()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

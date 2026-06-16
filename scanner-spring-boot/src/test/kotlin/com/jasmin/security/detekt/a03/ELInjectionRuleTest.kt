package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ELInjectionRuleTest {

    private val rule = ELInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags ELProcessor eval with variable`() {
        val code = """
            fun evaluate(userExpr: String): Any? = ELProcessor().eval(userExpr)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ELProcessor eval with interpolated expression`() {
        val code = """
            fun evaluate(prop: String): Any? = ELProcessor().eval("user.${'$'}prop")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags createValueExpression with variable`() {
        val code = """
            fun build(ctx: ELContext, expr: String) =
                factory.createValueExpression(expr, String::class.java)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores eval with literal expression`() {
        val code = """
            fun getUser(): Any? = ELProcessor().eval("user.name")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores createValueExpression with literal`() {
        val code = """
            fun build(ctx: ELContext) =
                factory.createValueExpression("#{user.name}", String::class.java)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on ResponseSplitting fixture`() {
        val code = """
            fun setHeader(response: HttpServletResponse, value: String) {
                response.addHeader("X-Custom", value)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

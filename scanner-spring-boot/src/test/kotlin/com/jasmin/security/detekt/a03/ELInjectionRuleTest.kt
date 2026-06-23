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
        // Real signature: createValueExpression(ELContext, String expression, Class<?>) — EL string is arg[1].
        val code = """
            fun build(ctx: ELContext, expr: String) =
                factory.createValueExpression(ctx, expr, String::class.java)
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
    fun `ignores createValueExpression with literal EL string as second arg`() {
        // The EL string is arg[1]; arg[0] is the ELContext. Must not fire on a literal expression.
        val code = """
            fun build(ctx: ELContext) =
                factory.createValueExpression(ctx, "#{user.name}", String::class.java)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores eval with constant string concatenation`() {
        val code = """
            fun getUser(): Any? = ELProcessor().eval("user." + "name")
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

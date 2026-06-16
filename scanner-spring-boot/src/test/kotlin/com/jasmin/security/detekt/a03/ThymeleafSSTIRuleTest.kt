package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ThymeleafSSTIRuleTest {

    private val rule = ThymeleafSSTIRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags templateEngine process with variable template name`() {
        val code = """
            fun render(templateName: String, ctx: Context): String =
                templateEngine.process(templateName, ctx)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags templateEngine process with interpolated template`() {
        val code = """
            fun render(name: String, ctx: Context): String =
                templateEngine.process("view-${'$'}name", ctx)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags myTemplateEngine process with request parameter`() {
        val code = """
            @GetMapping("/render")
            fun render(@RequestParam view: String, model: Model): String {
                val ctx = WebContext(request, response, servletContext)
                return myTemplateEngine.process(view, ctx)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores templateEngine process with literal template name`() {
        val code = """
            fun render(ctx: Context): String = templateEngine.process("user-profile", ctx)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores process called on unrelated receiver`() {
        val code = """
            fun handle(data: String): String = queryProcessor.process(data, ctx)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores top-level process call without receiver`() {
        val code = """
            fun render(name: String) = process(name)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on SpEL injection fixture`() {
        val code = """
            fun eval(expr: String): Any = parser.parseExpression(expr).getValue()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

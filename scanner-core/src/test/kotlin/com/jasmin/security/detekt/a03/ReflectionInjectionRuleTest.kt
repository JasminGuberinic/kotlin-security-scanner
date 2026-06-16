package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ReflectionInjectionRuleTest {

    private val rule = ReflectionInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags Class forName with variable class name`() {
        val code = """
            fun load(className: String): Class<*> = Class.forName(className)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Class forName with interpolated class name`() {
        val code = """
            fun load(pkg: String): Class<*> = Class.forName("com.${'$'}pkg.Handler")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Class forName with method call result`() {
        val code = """
            fun loadFromParam(req: HttpServletRequest): Class<*> =
                Class.forName(req.getParameter("class"))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores Class forName with literal class name`() {
        val code = """
            fun loadDriver(): Class<*> = Class.forName("com.mysql.cj.jdbc.Driver")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Class forName with well-known literal`() {
        val code = """
            fun loadJson(): Class<*> = Class.forName("com.fasterxml.jackson.databind.ObjectMapper")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on JNDI injection fixture`() {
        val code = """
            fun resolve(name: String): Any = ctx.lookup(name)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

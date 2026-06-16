package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class GroovyScriptInjectionRuleTest {

    private val rule = GroovyScriptInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags GroovyShell evaluate with variable script`() {
        val code = """
            fun run(userScript: String) = GroovyShell().evaluate(userScript)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags GroovyShell evaluate with interpolated script`() {
        val code = """
            fun run(expr: String) = GroovyShell().evaluate("println '${'$'}expr'")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ScriptEngine eval with variable`() {
        val code = """
            fun run(code: String) {
                val engine = ScriptEngineManager().getEngineByName("groovy")
                engine.eval(code)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags evaluate with method call result`() {
        val code = """
            fun run(req: HttpServletRequest) =
                GroovyShell().evaluate(req.getParameter("script"))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores evaluate with literal script`() {
        val code = """
            fun greet() = GroovyShell().evaluate("println 'hello world'")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores eval with literal script`() {
        val code = """
            fun calc() {
                val engine = ScriptEngineManager().getEngineByName("groovy")
                engine.eval("1 + 1")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on ReflectionInjection fixture`() {
        val code = """
            fun load(className: String): Class<*> = Class.forName(className)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

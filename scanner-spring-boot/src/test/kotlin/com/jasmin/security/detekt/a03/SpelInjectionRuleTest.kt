package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpelInjectionRuleTest {

    private val rule = SpelInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags parseExpression with variable`() {
        val code = """
            import org.springframework.expression.spel.standard.SpelExpressionParser
            fun eval(userInput: String): Any? {
                val parser = SpelExpressionParser()
                return parser.parseExpression(userInput).getValue()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags parseExpression with interpolated string`() {
        val code = """
            import org.springframework.expression.spel.standard.SpelExpressionParser
            fun eval(field: String): Any? {
                val parser = SpelExpressionParser()
                return parser.parseExpression("user.${'$'}field").getValue()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags parseRaw with variable`() {
        val code = """
            import org.springframework.expression.spel.standard.SpelExpressionParser
            fun eval(expr: String): Any? {
                return SpelExpressionParser().parseRaw(expr).getValue()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores parseExpression with string literal`() {
        val code = """
            import org.springframework.expression.spel.standard.SpelExpressionParser
            fun getAge(): Any? {
                val parser = SpelExpressionParser()
                return parser.parseExpression("user.age").getValue()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated parseExpression calls`() {
        val code = """
            fun parse(pattern: String) = Regex(pattern)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on CSRF disabled fixture`() {
        val code = """
            import org.springframework.security.config.annotation.web.builders.HttpSecurity
            fun configure(http: HttpSecurity) {
                http.csrf { it.disable() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

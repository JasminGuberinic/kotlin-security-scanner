package com.jasmin.security.detekt.a06

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class RegexInjectionRuleTest {

    private val rule = RegexInjectionRule(Config.empty)

    @Test
    fun `flags Pattern compile with a variable`() {
        val code = """
            import java.util.regex.Pattern
            fun match(userPattern: String) = Pattern.compile(userPattern)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Regex constructor with a variable`() {
        val code = """
            fun match(userPattern: String) = Regex(userPattern)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags toRegex on a variable`() {
        val code = """
            fun match(userPattern: String) = userPattern.toRegex()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Pattern compile with a literal`() {
        val code = """
            import java.util.regex.Pattern
            fun match() = Pattern.compile("^[a-z0-9]+$")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores toRegex on a literal`() {
        val code = """
            fun match() = "[a-z]+".toRegex()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

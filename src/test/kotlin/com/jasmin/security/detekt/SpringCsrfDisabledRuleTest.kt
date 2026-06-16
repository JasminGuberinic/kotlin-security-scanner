package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class SpringCsrfDisabledRuleTest {

    private val rule = SpringCsrfDisabledRule()

    @Test
    fun `flags csrf lambda DSL with disable`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http {
                    csrf { disable() }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isNotEmpty()
    }

    @Test
    fun `flags csrf disable fluent API`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.csrf().disable()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isNotEmpty()
    }

    @Test
    fun `flags csrf with method reference to disable`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.csrf(CsrfConfigurer::disable)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isNotEmpty()
    }

    @Test
    fun `ignores csrf enabled config`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http {
                    csrf { }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated disable calls`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.headers().disable()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag hardcoded credential patterns
    @Test
    fun `does not interfere with hardcoded credential code`() {
        val code = """val secretKey = "my-jwt-secret-value""""
        assertThat(rule.lint(code)).isEmpty()
    }
}

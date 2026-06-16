package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class PermissiveCorsRuleTest {

    private val rule = PermissiveCorsRule()

    @Test
    fun `flags allowedOrigins with wildcard`() {
        val code = """
            fun cors() {
                config.allowedOrigins("*")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags allowedOriginPatterns with wildcard`() {
        val code = """
            fun cors() {
                config.allowedOriginPatterns("*")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags addAllowedOrigin with wildcard`() {
        val code = """
            fun cors() {
                config.addAllowedOrigin("*")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores allowedOrigins with specific domain`() {
        val code = """
            fun cors() {
                config.allowedOrigins("https://app.example.com")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores allowedOrigins with multiple specific domains`() {
        val code = """
            fun cors() {
                config.allowedOrigins("https://app.example.com", "https://admin.example.com")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag CSRF patterns
    @Test
    fun `does not interfere with csrf disable code`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.csrf().disable()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

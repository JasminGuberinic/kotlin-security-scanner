package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringSecurityDebugEnabledRuleTest {

    private val rule = SpringSecurityDebugEnabledRule(Config.empty)

    @Test
    fun `flags EnableWebSecurity with debug true`() {
        val code = """
            @EnableWebSecurity(debug = true)
            class SecurityConfig {
                fun configure() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores EnableWebSecurity without debug`() {
        val code = """
            @EnableWebSecurity
            class SecurityConfig {
                fun configure() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores EnableWebSecurity with debug false`() {
        val code = """
            @EnableWebSecurity(debug = false)
            class SecurityConfig {
                fun configure() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with spring csrf disabled code`() {
        val code = """
            @Configuration
            class SecurityConfig {
                fun configure(http: HttpSecurity) {
                    http.csrf().disable()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

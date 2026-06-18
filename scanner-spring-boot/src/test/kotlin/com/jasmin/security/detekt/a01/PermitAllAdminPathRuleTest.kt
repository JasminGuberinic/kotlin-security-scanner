package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PermitAllAdminPathRuleTest {

    private val rule = PermitAllAdminPathRule(Config.empty)

    @Test
    fun `flags permitAll on admin path`() {
        val code = """
            http.authorizeHttpRequests {
                it.requestMatchers("/admin/users").permitAll()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags permitAll on actuator path`() {
        val code = """
            http.authorizeHttpRequests {
                it.requestMatchers("/actuator/health").permitAll()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags permitAll on management path`() {
        val code = """
            http.authorizeHttpRequests {
                it.requestMatchers("/management/info").permitAll()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores permitAll on public path`() {
        val code = """
            http.authorizeHttpRequests {
                it.requestMatchers("/public/welcome").permitAll()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores admin path with hasRole`() {
        val code = """
            http.authorizeHttpRequests {
                it.requestMatchers("/admin/users").hasRole("ADMIN")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with csrf disabled code`() {
        val code = """
            http.csrf { it.disable() }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

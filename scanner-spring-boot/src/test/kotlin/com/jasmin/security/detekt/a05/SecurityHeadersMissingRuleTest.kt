package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SecurityHeadersMissingRuleTest {

    private val rule = SecurityHeadersMissingRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags SecurityFilterChain without headers block`() {
        val code = """
            @Bean
            fun filterChain(http: HttpSecurity): SecurityFilterChain {
                http.authorizeHttpRequests { it.anyRequest().authenticated() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SecurityFilterChain with only csrf config and no headers`() {
        val code = """
            @Bean
            fun filterChain(http: HttpSecurity): SecurityFilterChain {
                http.csrf { it.disable() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SecurityFilterChain with cors but no headers`() {
        val code = """
            @Bean
            fun securityConfig(http: HttpSecurity): SecurityFilterChain {
                http.cors { }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores SecurityFilterChain with headers block`() {
        val code = """
            @Bean
            fun filterChain(http: HttpSecurity): SecurityFilterChain {
                http.headers { it.frameOptions { fo -> fo.deny() } }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-bean function named filterChain`() {
        val code = """
            fun filterChain(http: HttpSecurity): SecurityFilterChain {
                http.authorizeHttpRequests { it.anyRequest().authenticated() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on PermissiveCors fixture`() {
        val code = """
            @Bean
            fun corsConfiguration(): CorsConfiguration {
                val config = CorsConfiguration()
                config.allowedOrigins = listOf("*")
                return config
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HttpMethodOverrideRuleTest {

    private val rule = HttpMethodOverrideRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags HiddenHttpMethodFilter bean`() {
        val code = """
            @Bean
            fun hiddenHttpMethodFilter() = HiddenHttpMethodFilter()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags HiddenHttpMethodFilter constructor in val`() {
        val code = """
            val filter = HiddenHttpMethodFilter()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags HiddenHttpMethodFilter passed as argument`() {
        val code = """
            fun configure(filter: HiddenHttpMethodFilter = HiddenHttpMethodFilter()) { }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores other filter beans`() {
        val code = """
            @Bean
            fun corsFilter() = CorsFilter()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores string containing filter name`() {
        val code = """
            val filterName = "HiddenHttpMethodFilter"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on SecurityHeadersMissing fixture`() {
        val code = """
            @Bean
            fun filterChain(http: HttpSecurity): SecurityFilterChain {
                http.authorizeHttpRequests { it.anyRequest().authenticated() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

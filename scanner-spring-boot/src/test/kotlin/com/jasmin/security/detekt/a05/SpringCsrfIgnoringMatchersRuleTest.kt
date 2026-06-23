package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringCsrfIgnoringMatchersRuleTest {

    private val rule = SpringCsrfIgnoringMatchersRule(Config.empty)

    @Test
    fun `flags ignoringRequestMatchers`() {
        val code = """
            fun config(http: Any) {
                http.csrf { it.ignoringRequestMatchers("/api/**") }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags legacy ignoringAntMatchers`() {
        val code = """
            fun config(http: Any) {
                http.csrf().ignoringAntMatchers("/api/**")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores csrf configured without ignoring matchers`() {
        val code = """
            fun config(http: Any) {
                http.csrf { it.csrfTokenRepository(repo) }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

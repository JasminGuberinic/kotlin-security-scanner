package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ReactivePermitAllExchangeRuleTest {

    private val rule = ReactivePermitAllExchangeRule(Config.empty)

    @Test
    fun `flags anyExchange permitAll`() {
        val code = """
            fun config(http: Any) {
                http.authorizeExchange { it.anyExchange().permitAll() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags pathMatchers permitAll on an admin path`() {
        val code = """
            fun config(http: Any) {
                http.authorizeExchange { it.pathMatchers("/admin/**").permitAll() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores anyExchange authenticated`() {
        val code = """
            fun config(http: Any) {
                http.authorizeExchange { it.anyExchange().authenticated() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores permitAll on a public path`() {
        val code = """
            fun config(http: Any) {
                http.authorizeExchange { it.pathMatchers("/public/**").permitAll() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

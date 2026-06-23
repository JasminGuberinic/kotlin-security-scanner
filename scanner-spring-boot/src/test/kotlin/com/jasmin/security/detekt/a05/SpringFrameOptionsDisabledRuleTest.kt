package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringFrameOptionsDisabledRuleTest {

    private val rule = SpringFrameOptionsDisabledRule(Config.empty)

    @Test
    fun `flags frameOptions disabled in a lambda`() {
        val code = """
            fun config(http: Any) {
                http.headers { frameOptions { disable() } }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags fluent frameOptions disable`() {
        val code = """
            fun config(http: Any) {
                http.headers().frameOptions().disable()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores frameOptions sameOrigin`() {
        val code = """
            fun config(http: Any) {
                http.headers { frameOptions { sameOrigin() } }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

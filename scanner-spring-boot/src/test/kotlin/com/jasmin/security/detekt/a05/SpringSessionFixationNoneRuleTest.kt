package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringSessionFixationNoneRuleTest {

    private val rule = SpringSessionFixationNoneRule(Config.empty)

    @Test
    fun `flags sessionFixation none in a lambda`() {
        val code = """
            fun config(http: Any) {
                http.sessionManagement { sessionFixation { none() } }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags fluent sessionFixation none`() {
        val code = """
            fun config(http: Any) {
                http.sessionManagement().sessionFixation().none()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores sessionFixation migrateSession`() {
        val code = """
            fun config(http: Any) {
                http.sessionManagement { sessionFixation { migrateSession() } }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

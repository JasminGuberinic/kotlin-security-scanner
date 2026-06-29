package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxCookieNoHttpOnlyRuleTest {

    private val rule = VertxCookieNoHttpOnlyRule(Config.empty)

    @Test
    fun `flags cookie setHttpOnly false`() {
        val code = """
            fun c(id: String) = Cookie.cookie("session", id).setHttpOnly(false)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores cookie setHttpOnly true`() {
        val code = """
            fun c(id: String) = Cookie.cookie("session", id).setHttpOnly(true)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores setHttpOnly false on a non-cookie receiver`() {
        val code = """
            fun c() = SomeBuilder().setHttpOnly(false)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxInsecureCookieRuleTest {

    private val rule = VertxInsecureCookieRule(Config.empty)

    @Test
    fun `flags cookie setSecure false`() {
        val code = """
            fun c(id: String) = Cookie.cookie("session", id).setSecure(false)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores cookie setSecure true`() {
        val code = """
            fun c(id: String) = Cookie.cookie("session", id).setSecure(true)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores setSecure false on a non-cookie receiver`() {
        val code = """
            fun c() = ConnectionBuilder().setSecure(false)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

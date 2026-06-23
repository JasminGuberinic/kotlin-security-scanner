package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringBootCookieNotHttpOnlyRuleTest {

    private val rule = SpringBootCookieNotHttpOnlyRule(Config.empty)

    @Test
    fun `flags isHttpOnly set to false`() {
        val code = """
            fun handleLogin(response: HttpServletResponse) {
                val cookie = Cookie("SESSION", token)
                cookie.isHttpOnly = false
                response.addCookie(cookie)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ResponseCookie httpOnly(false)`() {
        val code = """
            fun handleLogin(): ResponseCookie {
                return ResponseCookie.from("AUTH", value).httpOnly(false).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores httpOnly assignment on a non-cookie receiver`() {
        val code = """
            fun configure(featureToggle: FeatureToggle) {
                featureToggle.httpOnly = false
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores isHttpOnly set to true`() {
        val code = """
            fun handleLogin(response: HttpServletResponse) {
                val cookie = Cookie("SESSION", token)
                cookie.isHttpOnly = true
                response.addCookie(cookie)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores ResponseCookie httpOnly(true)`() {
        val code = """
            val cookie = ResponseCookie.from("AUTH", value).httpOnly(true).secure(true).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with SpringCsrfDisabled fixture`() {
        val code = """
            fun securityConfig(http: HttpSecurity) {
                http.csrf { it.disable() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

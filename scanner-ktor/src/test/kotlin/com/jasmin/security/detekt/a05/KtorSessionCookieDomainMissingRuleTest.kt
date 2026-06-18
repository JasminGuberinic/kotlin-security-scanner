package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorSessionCookieDomainMissingRuleTest {

    private val rule = KtorSessionCookieDomainMissingRule(Config.empty)

    @Test
    fun `flags Sessions cookie without domain`() {
        val code = """
            fun configure() {
                install(Sessions) {
                    cookie<UserSession>("SESSION") {
                        cookie.secure = true
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Sessions cookie with domain set`() {
        val code = """
            install(Sessions) {
                cookie<UserSession>("SESSION") {
                    cookie.domain = "app.example.com"
                    cookie.secure = true
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Sessions without cookie`() {
        val code = """
            install(Sessions) {
                header<UserSession>("SESSION")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

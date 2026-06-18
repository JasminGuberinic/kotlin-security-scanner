package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorSslRedirectMissingRuleTest {

    private val rule = KtorSslRedirectMissingRule(Config.empty)

    @Test
    fun `flags routing without HttpsRedirect in file`() {
        val code = """
            fun Application.configureRouting() {
                routing {
                    get("/health") { call.respond("ok") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores routing when HttpsRedirect is present`() {
        val code = """
            fun Application.configure() {
                install(HttpsRedirect) { sslPort = 443 }
                routing {
                    get("/health") { call.respond("ok") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

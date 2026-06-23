package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorSslRedirectMissingRuleTest {

    private val rule = KtorSslRedirectMissingRule(Config.empty)

    @Test
    fun `flags routing in app setup that installs plugins but no HttpsRedirect`() {
        val code = """
            fun Application.module() {
                install(ContentNegotiation) { json() }
                install(CallLogging)
                routing {
                    get("/health") { call.respond("ok") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores file that only declares routes`() {
        val code = """
            fun Application.routes() {
                routing {
                    get("/") {}
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
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

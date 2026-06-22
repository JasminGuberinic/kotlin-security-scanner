package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorWebSocketNoAuthRuleTest {

    private val rule = KtorWebSocketNoAuthRule(Config.empty)

    @Test
    fun `flags webSocket without authenticate`() {
        val code = """
            fun Application.configureRoutes() {
                routing {
                    webSocket("/chat") {
                        for (frame in incoming) { outgoing.send(frame) }
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores webSocket inside authenticate block`() {
        val code = """
            fun Application.configureRoutes() {
                routing {
                    authenticate("jwt") {
                        webSocket("/chat") {
                            for (frame in incoming) { outgoing.send(frame) }
                        }
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with missing auth routing code`() {
        val code = """
            fun Application.configureRoutes() {
                routing {
                    get("/admin/users") { call.respondText("admin data") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

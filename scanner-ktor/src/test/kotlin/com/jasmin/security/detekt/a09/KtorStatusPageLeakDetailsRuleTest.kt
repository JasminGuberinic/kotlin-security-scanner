package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorStatusPageLeakDetailsRuleTest {

    private val rule = KtorStatusPageLeakDetailsRule(Config.empty)

    @Test
    fun `flags exception handler responding with cause message`() {
        val code = """
            install(StatusPages) {
                exception<Exception> { cause ->
                    call.respond(HttpStatusCode.InternalServerError, cause.message ?: "error")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags exception handler responding with cause toString`() {
        val code = """
            install(StatusPages) {
                exception<Throwable> { cause ->
                    call.respondText(cause.toString(), status = HttpStatusCode.InternalServerError)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags exception handler exposing stack trace`() {
        val code = """
            install(StatusPages) {
                exception<Exception> { e ->
                    call.respond(HttpStatusCode.InternalServerError, e.stackTrace.toString())
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores exception handler with generic message`() {
        val code = """
            install(StatusPages) {
                exception<Exception> { _ ->
                    call.respond(HttpStatusCode.InternalServerError, "Internal server error")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores exception handler that only logs`() {
        val code = """
            install(StatusPages) {
                exception<Exception> { cause ->
                    application.log.error("Error", cause)
                    call.respond(HttpStatusCode.InternalServerError, "Something went wrong")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with logging credentials code`() {
        val code = """
            post("/login") {
                val username = call.parameters["username"]
                val password = call.parameters["password"]
                application.log.info("Login: user=${'$'}username")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

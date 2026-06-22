package com.jasmin.security.detekt.a04

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorRawCallReceiveRuleTest {

    private val rule = KtorRawCallReceiveRule(Config.empty)

    @Test
    fun `flags call receive Any`() {
        val code = """
            post("/update") {
                val body = call.receive<Any>()
                println(body)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags call receive HashMap`() {
        val code = """
            post("/data") {
                val body = call.receive<HashMap<String, Any>>()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags call receive Map`() {
        val code = """
            post("/data") {
                val body = call.receive<Map<String, Any>>()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores call receive with specific data class`() {
        val code = """
            post("/users") {
                val request = call.receive<CreateUserRequest>()
                val user = userService.create(request)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores call receive String for text body`() {
        val code = """
            post("/text") {
                val body = call.receive<String>()
                call.respondText("Echo: ${'$'}body")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with WebSocket no auth code`() {
        val code = """
            routing {
                authenticate("jwt") {
                    webSocket("/chat") {
                        for (frame in incoming) { outgoing.send(frame) }
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

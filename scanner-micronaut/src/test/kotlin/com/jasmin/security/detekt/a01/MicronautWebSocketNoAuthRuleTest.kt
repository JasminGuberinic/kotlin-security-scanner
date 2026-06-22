package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautWebSocketNoAuthRuleTest {

    private val rule = MicronautWebSocketNoAuthRule(Config.empty)

    @Test
    fun `flags ServerWebSocket class without Secured`() {
        val code = """
            import io.micronaut.websocket.annotation.ServerWebSocket
            @ServerWebSocket("/chat")
            class ChatHandler
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ServerWebSocket with OnMessage but no Secured`() {
        val code = """
            import io.micronaut.websocket.annotation.ServerWebSocket
            import io.micronaut.websocket.annotation.OnMessage
            @ServerWebSocket("/updates")
            class UpdateHandler {
                @OnMessage
                fun onMessage(message: String) {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores ServerWebSocket with class-level Secured`() {
        val code = """
            import io.micronaut.websocket.annotation.ServerWebSocket
            import io.micronaut.security.annotation.Secured
            import io.micronaut.security.rules.SecurityRule
            @ServerWebSocket("/chat")
            @Secured(SecurityRule.IS_AUTHENTICATED)
            class ChatHandler
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores regular controller class`() {
        val code = """
            import io.micronaut.http.annotation.Controller
            @Controller("/api")
            class ApiController
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

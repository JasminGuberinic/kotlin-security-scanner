package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautInsecureHttpClientRuleTest {

    private val rule = MicronautInsecureHttpClientRule(Config.empty)

    @Test
    fun `flags Client with http URL`() {
        val code = """
            import io.micronaut.http.client.annotation.Client
            @Client("http://user-service")
            interface UserClient
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Client with http URL including port`() {
        val code = """
            import io.micronaut.http.client.annotation.Client
            @Client("http://localhost:8080")
            interface PaymentClient
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Client with https URL`() {
        val code = """
            import io.micronaut.http.client.annotation.Client
            @Client("https://user-service")
            interface UserClient
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Client with service ID — no scheme`() {
        val code = """
            import io.micronaut.http.client.annotation.Client
            @Client("user-service")
            interface UserClient
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Client with property placeholder`() {
        val code = """
            import io.micronaut.http.client.annotation.Client
            @Client("${'$'}{user-service.url}")
            interface UserClient
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on missing secured code`() {
        val code = """
            import io.micronaut.http.annotation.Get
            class UserController {
                @Get
                fun list(): List<String> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

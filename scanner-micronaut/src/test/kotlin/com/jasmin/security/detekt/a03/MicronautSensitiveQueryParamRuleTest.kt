package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautSensitiveQueryParamRuleTest {

    private val rule = MicronautSensitiveQueryParamRule(Config.empty)

    @Test
    fun `flags QueryValue parameter named password`() {
        val code = """
            import io.micronaut.http.annotation.Get
            import io.micronaut.http.annotation.QueryValue
            class AuthController {
                @Get("/login")
                fun login(@QueryValue password: String): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags QueryValue with token in annotation value`() {
        val code = """
            import io.micronaut.http.annotation.Get
            import io.micronaut.http.annotation.QueryValue
            class ApiController {
                @Get("/api")
                fun callApi(@QueryValue("api_key") key: String): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags QueryValue parameter named secret`() {
        val code = """
            import io.micronaut.http.annotation.Get
            import io.micronaut.http.annotation.QueryValue
            class WebhookController {
                @Get("/webhook")
                fun webhook(@QueryValue secret: String): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores QueryValue with non-sensitive name`() {
        val code = """
            import io.micronaut.http.annotation.Get
            import io.micronaut.http.annotation.QueryValue
            class UserController {
                @Get("/users")
                fun list(@QueryValue page: Int): List<String> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Body parameter with sensitive name`() {
        val code = """
            import io.micronaut.http.annotation.Post
            import io.micronaut.http.annotation.Body
            data class LoginRequest(val password: String)
            class AuthController {
                @Post("/login")
                fun login(@Body request: LoginRequest): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on hardcoded JWT secret code`() {
        val code = """
            class JwtUtil {
                val key = "literal"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

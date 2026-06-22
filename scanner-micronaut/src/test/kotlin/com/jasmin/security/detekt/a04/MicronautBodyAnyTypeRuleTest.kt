package com.jasmin.security.detekt.a04

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautBodyAnyTypeRuleTest {

    private val rule = MicronautBodyAnyTypeRule(Config.empty)

    @Test
    fun `flags Body typed as Any`() {
        val code = """
            import io.micronaut.http.annotation.Post
            import io.micronaut.http.annotation.Body
            class DataController {
                @Post("/data")
                fun receive(@Body body: Any): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Body typed as Map`() {
        val code = """
            import io.micronaut.http.annotation.Post
            import io.micronaut.http.annotation.Body
            class DataController {
                @Post("/data")
                fun receive(@Body body: Map<String, Any>): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Body typed as concrete DTO`() {
        val code = """
            import io.micronaut.http.annotation.Post
            import io.micronaut.http.annotation.Body
            data class CreateUserRequest(val name: String, val email: String)
            class UserController {
                @Post("/users")
                fun create(@Body request: CreateUserRequest): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores parameter without Body annotation`() {
        val code = """
            class UserService {
                fun process(data: Any): String = data.toString()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on open redirect code`() {
        val code = """
            import io.micronaut.http.HttpResponse
            import java.net.URI
            class Controller {
                fun home(): HttpResponse<*> = HttpResponse.seeOther<Any>(URI("/home"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

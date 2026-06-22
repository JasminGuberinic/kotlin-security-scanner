package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautExceptionMessageLeakRuleTest {

    private val rule = MicronautExceptionMessageLeakRule(Config.empty)

    @Test
    fun `flags Error handler returning exception message`() {
        val code = """
            import io.micronaut.http.annotation.Error
            import io.micronaut.http.HttpResponse
            class ErrorHandler {
                @Error
                fun handle(e: Exception): HttpResponse<String> =
                    HttpResponse.serverError(e.message)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Error handler with message in string template`() {
        val code = """
            import io.micronaut.http.annotation.Error
            import io.micronaut.http.HttpResponse
            class ErrorHandler {
                @Error
                fun handle(e: Exception): HttpResponse<String> =
                    HttpResponse.serverError("Error: ${'$'}{e.message}")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Error handler returning generic message`() {
        val code = """
            import io.micronaut.http.annotation.Error
            import io.micronaut.http.HttpResponse
            class ErrorHandler {
                @Error
                fun handle(e: Exception): HttpResponse<String> =
                    HttpResponse.serverError("Internal server error")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores regular function with message reference`() {
        val code = """
            class UserService {
                fun process(e: Exception): String = e.message ?: "unknown"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on hardcoded secret code`() {
        val code = """
            class Config {
                val key = "literal"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

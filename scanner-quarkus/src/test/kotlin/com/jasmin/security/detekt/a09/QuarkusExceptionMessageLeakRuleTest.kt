package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusExceptionMessageLeakRuleTest {

    private val rule = QuarkusExceptionMessageLeakRule(Config.empty)

    @Test
    fun `flags @Provider ExceptionMapper returning ex_message`() {
        val code = """
            @Provider
            fun toResponse(e: Exception): Response {
                return Response.serverError().entity(e.message).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags @ServerExceptionMapper returning exception stackTrace`() {
        val code = """
            @ServerExceptionMapper
            fun handle(exception: RuntimeException): Response {
                return Response.status(500).entity(exception.stackTraceToString()).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores @Provider ExceptionMapper returning generic message`() {
        val code = """
            @Provider
            fun toResponse(e: Exception): Response {
                return Response.serverError().entity("Internal server error").build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores regular method with exception message`() {
        val code = """
            fun logError(e: Exception) {
                logger.error("Error: ${'$'}{e.message}")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with QuarkusSmallRyeHealth fixture`() {
        val code = """
            quarkus.smallrye-health.ui.enable=false
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

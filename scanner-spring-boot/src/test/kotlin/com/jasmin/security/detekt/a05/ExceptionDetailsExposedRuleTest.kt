package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ExceptionDetailsExposedRuleTest {

    private val rule = ExceptionDetailsExposedRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags ExceptionHandler returning e message`() {
        val code = """
            @ExceptionHandler
            fun handle(e: Exception) = ResponseEntity.badRequest().body(e.message)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ExceptionHandler with localizedMessage`() {
        val code = """
            @ExceptionHandler
            fun handle(e: Exception): String = e.localizedMessage
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ExceptionHandler with printStackTrace`() {
        val code = """
            @ExceptionHandler
            fun handle(e: RuntimeException): String {
                e.printStackTrace()
                return "error"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores ExceptionHandler with generic message`() {
        val code = """
            @ExceptionHandler
            fun handle(e: Exception) = ResponseEntity.internalServerError().body("An error occurred")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores ExceptionHandler that only logs e message but returns generic body`() {
        val code = """
            @ExceptionHandler
            fun handle(e: Exception): ResponseEntity<String> {
                logger.error("Request failed", e.message)
                return ResponseEntity.internalServerError().body("An error occurred")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores regular function returning exception message`() {
        val code = """
            fun logError(e: Exception) = logger.error(e.message)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on HttpMethodOverride fixture`() {
        val code = """
            @Bean
            fun hiddenHttpMethodFilter() = HiddenHttpMethodFilter()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

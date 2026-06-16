package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class OpenRedirectRuleTest {

    private val rule = OpenRedirectRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags redirect with interpolated URL`() {
        val code = """
            import org.springframework.stereotype.Controller
            @Controller
            class AuthController {
                fun login(returnUrl: String): String = "redirect:${'$'}returnUrl"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags redirect built with concatenation`() {
        val code = """
            import org.springframework.stereotype.Controller
            @Controller
            class AuthController {
                fun login(next: String): String = "redirect:" + next
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags redirect with interpolated path segment`() {
        val code = """
            @Controller
            class UserController {
                fun afterCreate(id: Long): String = "redirect:/users/${'$'}id/profile"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores literal redirect path`() {
        val code = """
            @Controller
            class HomeController {
                fun home(): String = "redirect:/dashboard"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores forward view name`() {
        val code = """
            @Controller
            class ViewController {
                fun view(id: Long): String = "forward:/templates/user"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores interpolated non-redirect string`() {
        val code = """
            @Controller
            class MessageController {
                fun message(name: String): String = "hello ${'$'}name"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on SpEL injection fixture`() {
        val code = """
            import org.springframework.expression.spel.standard.SpelExpressionParser
            fun eval(expr: String): Any? = SpelExpressionParser().parseExpression(expr).getValue()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

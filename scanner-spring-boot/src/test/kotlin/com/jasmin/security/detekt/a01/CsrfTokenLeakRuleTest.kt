package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class CsrfTokenLeakRuleTest {

    private val rule = CsrfTokenLeakRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags addAttribute with _csrf key`() {
        val code = """
            fun form(model: Model, csrf: CsrfToken): String {
                model.addAttribute("_csrf", csrf)
                return "form"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags addAttribute with csrfToken key`() {
        val code = """
            fun form(model: Model, token: CsrfToken): String {
                model.addAttribute("csrfToken", token)
                return "form"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags addAttribute with csrf key (lowercase)`() {
        val code = """
            fun api(model: Model, csrf: String): String {
                model.addAttribute("csrf", csrf)
                return "api"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores addAttribute with non-sensitive key`() {
        val code = """
            fun form(model: Model, user: User): String {
                model.addAttribute("user", user)
                return "form"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores addAttribute with token key — too generic`() {
        val code = """
            fun form(model: Model, accessToken: String): String {
                model.addAttribute("accessToken", accessToken)
                return "form"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores addAttribute with interpolated key — dynamic key is opaque`() {
        val code = """
            fun form(model: Model, key: String, value: Any): String {
                model.addAttribute("attr_${'$'}key", value)
                return "form"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on DisabledHttpSecurity fixture`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.authorizeHttpRequests { auth ->
                    auth.anyRequest().permitAll()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

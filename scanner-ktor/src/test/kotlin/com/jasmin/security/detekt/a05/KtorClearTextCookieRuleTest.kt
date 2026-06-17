package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorClearTextCookieRuleTest {

    private val rule = KtorClearTextCookieRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags Cookie constructor without secure flag`() {
        val code = """
            fun configure() {
                val cookie = Cookie("session", sessionId)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Cookie with explicit secure equals false`() {
        val code = """
            fun configure() {
                val cookie = Cookie("session", sessionId, secure = false)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores Cookie with secure true`() {
        val code = """
            fun configure() {
                val cookie = Cookie("session", sessionId, secure = true, httpOnly = true)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Cookie with no arguments`() {
        val code = """
            fun configure() {
                val cookie = Cookie()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on KtorPermissiveCors fixture`() {
        val code = """
            fun configure() {
                install(CORS) { anyHost() }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

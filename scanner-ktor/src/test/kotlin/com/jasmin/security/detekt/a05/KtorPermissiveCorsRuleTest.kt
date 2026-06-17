package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorPermissiveCorsRuleTest {

    private val rule = KtorPermissiveCorsRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags CORS install with anyHost`() {
        val code = """
            fun configure() {
                install(CORS) {
                    anyHost()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags CORS anyHost with other config`() {
        val code = """
            fun configure() {
                install(CORS) {
                    anyHost()
                    allowMethod(HttpMethod.Post)
                    allowHeader(HttpHeaders.ContentType)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores CORS install with specific host`() {
        val code = """
            install(CORS) {
                allowHost("api.example.com", schemes = listOf("https"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-CORS install`() {
        val code = """
            install(Sessions) {
                cookie<UserSession>("SESSION")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores CORS without anyHost`() {
        val code = """
            install(CORS) {
                allowMethod(HttpMethod.Get)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on KtorMissingAuth fixture`() {
        val code = """
            routing {
                get("/health") { call.respond("UP") }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

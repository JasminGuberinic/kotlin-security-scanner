package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorInsecureCookieSessionRuleTest {

    private val rule = KtorInsecureCookieSessionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags Sessions cookie without transform`() {
        val code = """
            fun configure() {
                install(Sessions) {
                    cookie<UserSession>("USER_SESSION")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Sessions cookie with only maxAge and no transform`() {
        val code = """
            fun configure() {
                install(Sessions) {
                    cookie<UserSession>("SESSION") {
                        cookie.maxAgeInSeconds = 3600
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores Sessions cookie with transform`() {
        val code = """
            install(Sessions) {
                cookie<UserSession>("SESSION") {
                    transform(SessionTransportTransformerEncrypt(encKey, authKey))
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Sessions install without cookie`() {
        val code = """
            install(Sessions) {
                header<UserSession>("X-Auth-Token")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-Sessions install`() {
        val code = """
            install(ContentNegotiation) {
                json()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on KtorPermissiveCors fixture`() {
        val code = """
            install(CORS) { anyHost() }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

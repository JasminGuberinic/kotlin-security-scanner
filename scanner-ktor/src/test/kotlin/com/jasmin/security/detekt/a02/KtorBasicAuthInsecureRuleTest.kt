package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorBasicAuthInsecureRuleTest {

    private val rule = KtorBasicAuthInsecureRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags basic auth with name and configure block`() {
        val code = """
            fun configure() {
                install(Authentication) {
                    basic("basic-auth") {
                        realm = "example"
                        validate { credentials -> null }
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags basic auth without name`() {
        val code = """
            fun configure() {
                install(Authentication) {
                    basic {
                        validate { credentials -> null }
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores JWT auth configuration`() {
        val code = """
            fun configure() {
                install(Authentication) {
                    jwt("jwt-auth") {
                        verifier(JwtConfig.verifier)
                        validate { credentials -> JWTPrincipal(credentials.payload) }
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores session auth configuration`() {
        val code = """
            fun configure() {
                install(Authentication) {
                    session<UserSession>("auth-session") {
                        validate { session -> session }
                    }
                }
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

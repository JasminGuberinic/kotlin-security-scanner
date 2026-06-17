package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorHardcodedSecretKeyRuleTest {

    private val rule = KtorHardcodedSecretKeyRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags SessionTransportTransformerEncrypt with literal key`() {
        val code = """
            fun configure() {
                install(Sessions) {
                    cookie<UserSession>("SESSION") {
                        transform(SessionTransportTransformerEncrypt("deadbeef01234567", "cafebabe98765432"))
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SessionTransportTransformerMessageAuthentication with literal key`() {
        val code = """
            fun configure() {
                install(Sessions) {
                    cookie<UserSession>("SESSION") {
                        transform(SessionTransportTransformerMessageAuthentication("my-hmac-secret"))
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores SessionTransportTransformerEncrypt with variable keys`() {
        val code = """
            fun configure() {
                install(Sessions) {
                    cookie<UserSession>("SESSION") {
                        transform(SessionTransportTransformerEncrypt(encryptKey, signKey))
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores other function calls`() {
        val code = """
            fun configure() {
                install(Sessions) {
                    cookie<UserSession>("USER_SESSION")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on KtorInsecureCookieSession fixture`() {
        val code = """
            fun configure() {
                install(Sessions) {
                    cookie<UserSession>("USER_SESSION")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

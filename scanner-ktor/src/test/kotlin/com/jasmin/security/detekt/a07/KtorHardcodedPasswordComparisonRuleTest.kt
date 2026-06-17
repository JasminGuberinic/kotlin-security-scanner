package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorHardcodedPasswordComparisonRuleTest {

    private val rule = KtorHardcodedPasswordComparisonRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags credentials password compared to literal`() {
        val code = """
            fun validate() {
                if (credentials.password == "admin123") {
                    return null
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags literal compared to credentials password`() {
        val code = """
            fun validate() {
                val isValid = "secret" == credentials.password
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores password match via encoder`() {
        val code = """
            fun validate() {
                val matches = passwordEncoder.matches(credentials.password, storedHash)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores string equality without password field`() {
        val code = """
            fun validate() {
                if (request.username == "admin") {
                    processRequest()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on KtorHardcodedSecretKey fixture`() {
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
}

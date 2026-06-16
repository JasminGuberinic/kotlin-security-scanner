package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardUnencryptedJwtSecretRuleTest {

    private val rule = DropwizardUnencryptedJwtSecretRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags setSecretProvider with lambda returning literal`() {
        val code = """
            fun filter() = JwtAuthFilter.Builder<User>()
                .setSecretProvider("hardcoded-jwt-secret")
                .buildAuthFilter()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setSecretProvider with short literal`() {
        val code = """
            val filter = JwtAuthFilter.Builder<Principal>().setSecretProvider("secret").buildAuthFilter()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores setSecretProvider with env var`() {
        val code = """
            fun filter() = JwtAuthFilter.Builder<User>()
                .setSecretProvider(System.getenv("JWT_SECRET"))
                .buildAuthFilter()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores setSecretProvider with variable`() {
        val code = """
            fun filter(secret: String) = JwtAuthFilter.Builder<User>()
                .setSecretProvider(secret)
                .buildAuthFilter()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on DropwizardOpenRedirect fixture`() {
        val code = """
            fun redirect(url: String): Response = Response.seeOther(URI(url)).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

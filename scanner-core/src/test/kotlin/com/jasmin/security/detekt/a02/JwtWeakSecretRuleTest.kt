package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtWeakSecretRuleTest {

    private val rule = JwtWeakSecretRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags HMAC256 with literal secret`() {
        val code = """
            fun algorithm() = Algorithm.HMAC256("my-super-secret-key")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags HMAC512 with literal secret`() {
        val code = """
            fun algorithm() = Algorithm.HMAC512("another-hardcoded-secret")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags signWith with literal secret as second arg`() {
        val code = """
            fun token(): String =
                Jwts.builder().signWith(SignatureAlgorithm.HS256, "hardcoded-secret").compact()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags signWith with literal key as first arg`() {
        val code = """
            fun token(): String = Jwts.builder().signWith("plain-text-secret").compact()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores HMAC256 with env var`() {
        val code = """
            fun algorithm() = Algorithm.HMAC256(System.getenv("JWT_SECRET"))
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores signWith with SecretKey object`() {
        val code = """
            fun token(secret: SecretKey): String =
                Jwts.builder().signWith(secret).compact()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores HMAC256 with interpolated string`() {
        val code = """
            fun algorithm(prefix: String) = Algorithm.HMAC256("${'$'}prefix-key")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on JwtNoneAlgorithm fixture`() {
        val code = """
            fun verifier() = JWT.require(Algorithm.none()).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

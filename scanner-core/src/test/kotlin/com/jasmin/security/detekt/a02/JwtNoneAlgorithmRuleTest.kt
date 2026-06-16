package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtNoneAlgorithmRuleTest {

    private val rule = JwtNoneAlgorithmRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags signWith SignatureAlgorithm NONE`() {
        val code = """
            fun buildToken(): String =
                Jwts.builder().signWith(SignatureAlgorithm.NONE, "").compact()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags signWith NONE constant reference`() {
        val code = """
            fun buildToken(claims: Map<String, Any>): String =
                Jwts.builder().setClaims(claims).signWith(alg.NONE).compact()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Algorithm none from auth0`() {
        val code = """
            fun verifier() = JWT.require(Algorithm.none()).build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores signWith HS256`() {
        val code = """
            fun buildToken(secret: SecretKey): String =
                Jwts.builder().signWith(SignatureAlgorithm.HS256, secret).compact()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Algorithm HMAC256`() {
        val code = """
            fun verifier(secret: String) = JWT.require(Algorithm.HMAC256(secret)).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores none method on unrelated receiver`() {
        val code = """
            fun noop() = Optional.none()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on WeakHashAlgorithm fixture`() {
        val code = """
            fun hash(data: ByteArray) = MessageDigest.getInstance("MD5").digest(data)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

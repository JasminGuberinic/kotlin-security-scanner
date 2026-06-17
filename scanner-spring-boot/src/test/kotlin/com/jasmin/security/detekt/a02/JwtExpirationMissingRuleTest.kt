package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JwtExpirationMissingRuleTest {

    private val rule = JwtExpirationMissingRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags compact without setExpiration`() {
        val code = """
            fun token() = Jwts.builder().subject("user").compact()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags compact with claims but no expiration`() {
        val code = """
            fun token() = Jwts.builder().subject("user").claim("role", "admin").compact()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags compact with signWith but no expiration`() {
        val code = """
            fun token() = Jwts.builder().subject("user").signWith(key).compact()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores compact with setExpiration`() {
        val code = """
            fun token() = Jwts.builder().subject("user").setExpiration(expDate).compact()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores compact with expiration (JJWT 0dot12)`() {
        val code = """
            fun token() = Jwts.builder().subject("user").expiration(date).compact()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-builder compact call`() {
        val code = """
            fun compress(data: ByteArray) = zip.compact()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on InsecureRedisConnection fixture`() {
        val code = """
            fun redis() = RedisStandaloneConfiguration("localhost", 6379)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

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

    // ── Nimbus JOSE JWT (MACSigner / MACVerifier) ─────────────────────────────

    @Test
    fun `flags MACSigner with literal string`() {
        val code = """
            import com.nimbusds.jose.crypto.MACSigner
            class JwtFactory {
                fun sign() = MACSigner("super-secret-key-min-256-bits!!")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags MACVerifier with literal string`() {
        val code = """
            import com.nimbusds.jose.crypto.MACVerifier
            class JwtFactory {
                fun verify() = MACVerifier("super-secret-key-min-256-bits!!")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores MACSigner with variable`() {
        val code = """
            import com.nimbusds.jose.crypto.MACSigner
            class JwtFactory {
                fun build(secret: ByteArray) = MACSigner(secret)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── JJWT v1 (Keys.hmacShaKeyFor) ─────────────────────────────────────────

    @Test
    fun `flags hmacShaKeyFor with literal toByteArray`() {
        val code = """
            import io.jsonwebtoken.security.Keys
            class JwtUtil {
                val key = Keys.hmacShaKeyFor("my-secret-key-that-is-long-enough".toByteArray())
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags hmacShaKeyFor with plain literal`() {
        val code = """
            import io.jsonwebtoken.security.Keys
            class JwtUtil {
                val key = Keys.hmacShaKeyFor("my-secret-key-that-is-long-enough")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores hmacShaKeyFor with variable`() {
        val code = """
            import io.jsonwebtoken.security.Keys
            class JwtUtil {
                fun build(secret: ByteArray) = Keys.hmacShaKeyFor(secret)
            }
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

package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusUnsafeHeaderRuleTest {

    private val rule = QuarkusUnsafeHeaderRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags Response header with variable value`() {
        val code = """
            fun build(userAgent: String): Response =
                Response.ok().header("X-Custom", userAgent).build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Response header with interpolated value`() {
        val code = """
            fun build(version: String): Response =
                Response.ok().header("X-App-Version", "v${'$'}version").build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Response status header with dynamic Content-Type`() {
        val code = """
            fun proxy(contentType: String): Response =
                Response.status(200).header("Content-Type", contentType).build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Response header with method call result`() {
        val code = """
            fun mirror(req: Request): Response =
                Response.ok().header("X-Forwarded", req.getHeaderString("Origin")).build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores Response header with literal value`() {
        val code = """
            fun secure(): Response =
                Response.ok().header("X-Frame-Options", "DENY").build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores header call without Response receiver`() {
        val code = """
            fun setHeaders(builder: HeadersBuilder, value: String) {
                builder.header("X-Custom", value)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on InsecureCookie fixture`() {
        val code = """
            fun sessionCookie(token: String) = NewCookie("session", token)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

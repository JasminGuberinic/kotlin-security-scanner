package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecureCookieRuleTest {

    private val rule = InsecureCookieRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags NewCookie with 2 args — no Secure or HttpOnly`() {
        val code = """
            fun sessionCookie(token: String) = NewCookie("session", token)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags NewCookie 8-arg with secure=false`() {
        // Jakarta: NewCookie(name, value, path, domain, comment, maxAge, secure, httpOnly)
        val code = """
            fun insecureCookie(token: String) =
                NewCookie("s", token, "/", null, "", 3600, false, true)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags NewCookie 6-arg — secure defaults to false`() {
        // NewCookie(name, value, path, domain, comment, maxAge) — no secure parameter
        val code = """
            fun insecureCookie(token: String) =
                NewCookie("s", token, "/", "example.com", "", 3600)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags NewCookie 7-arg with secure=false`() {
        val code = """
            fun insecureCookie(token: String) =
                NewCookie("s", token, "/", "example.com", "", 3600, false)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags NewCookie 2 args even with constant token`() {
        val code = """
            val TOKEN = "static-test-token"
            fun devCookie() = NewCookie("dev", TOKEN)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores NewCookie 8-arg with secure=true`() {
        // secure=true at index 6, httpOnly=false at index 7 — still secure on the wire
        val code = """
            fun secureCookie(token: String) =
                NewCookie("s", token, "/", null, "", 3600, true, false)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores NewCookie 7-arg with secure=true`() {
        val code = """
            fun secureCookie(token: String) =
                NewCookie("s", token, "/", "example.com", "", 3600, true)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores NewCookie builder pattern`() {
        val code = """
            fun buildCookie(token: String) =
                NewCookie.Builder("session").value(token).secure(true).httpOnly(true).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores NewCookie with 3 args — different overload`() {
        val code = """
            fun pathCookie(token: String) = NewCookie("session", token, "/api")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on DropwizardMissingAuth fixture`() {
        val code = """
            import javax.ws.rs.GET
            import javax.ws.rs.Path
            @Path("/public")
            class PublicResource {
                @GET
                fun health(): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

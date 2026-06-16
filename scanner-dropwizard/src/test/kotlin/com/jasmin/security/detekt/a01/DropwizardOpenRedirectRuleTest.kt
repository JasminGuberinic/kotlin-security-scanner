package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardOpenRedirectRuleTest {

    private val rule = DropwizardOpenRedirectRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags seeOther with URI from variable`() {
        val code = """
            fun redirect(next: String): Response =
                Response.seeOther(URI(next)).build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags temporaryRedirect with URI from variable`() {
        val code = """
            fun redirect(url: String): Response =
                Response.temporaryRedirect(URI(url)).build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags seeOther with URI from interpolated string`() {
        val code = """
            fun redirectUser(host: String): Response =
                Response.seeOther(URI("https://${'$'}host/login")).build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags seeOther with bare variable`() {
        val code = """
            fun redirectToUri(target: URI): Response =
                Response.seeOther(target).build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores seeOther with URI from literal`() {
        val code = """
            fun backToDashboard(): Response =
                Response.seeOther(URI("/dashboard")).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores temporaryRedirect with URI from literal`() {
        val code = """
            fun movedEndpoint(): Response =
                Response.temporaryRedirect(URI("/api/v2/users")).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on InsecureTls fixture`() {
        val code = """
            val factory = SslContextFactory()
            factory.setSupportedProtocols(arrayOf("TLSv1.0"))
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

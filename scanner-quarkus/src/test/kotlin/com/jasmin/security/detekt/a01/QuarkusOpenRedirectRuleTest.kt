package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusOpenRedirectRuleTest {

    private val rule = QuarkusOpenRedirectRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags temporaryRedirect with dynamic URI`() {
        val code = """
            fun redirect(target: String): Response {
                return Response.temporaryRedirect(URI(target)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags seeOther with interpolated URI`() {
        val code = """
            fun redirect(host: String): Response {
                return Response.seeOther(URI("https://${'$'}{host}/home")).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores temporaryRedirect with literal URI`() {
        val code = """
            fun redirect(): Response {
                return Response.temporaryRedirect(URI("/dashboard")).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores seeOther with full literal URI`() {
        val code = """
            fun redirect(): Response {
                return Response.seeOther(URI("https://example.com/callback")).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on QuarkusMissingAuth fixture`() {
        val code = """
            @Path("/users")
            class UserResource {
                @GET
                fun list(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

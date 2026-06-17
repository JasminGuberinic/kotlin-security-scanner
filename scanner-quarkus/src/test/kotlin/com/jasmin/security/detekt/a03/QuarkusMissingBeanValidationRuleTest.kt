package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusMissingBeanValidationRuleTest {

    private val rule = QuarkusMissingBeanValidationRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags POST method without Valid on entity parameter`() {
        val code = """
            @POST
            fun createUser(userDto: UserDto): Response {
                return Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags PUT method without Valid on body parameter`() {
        val code = """
            @PUT
            @Path("/{id}")
            fun updateUser(@PathParam("id") id: Long, userDto: UserDto): Response {
                return Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores POST method with Valid annotation`() {
        val code = """
            @POST
            fun createUser(@Valid userDto: UserDto): Response {
                return Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores GET method`() {
        val code = """
            @GET
            fun listUsers(userDto: UserDto): Response {
                return Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores POST method with only JAX-RS binding params`() {
        val code = """
            @POST
            fun search(@QueryParam("q") query: String): Response {
                return Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on QuarkusOpenRedirect fixture`() {
        val code = """
            fun redirect(target: String): Response {
                return Response.temporaryRedirect(URI(target)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

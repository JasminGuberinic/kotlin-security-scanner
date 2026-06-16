package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusPermitAllSensitiveRuleTest {

    private val rule = QuarkusPermitAllSensitiveRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags DELETE with PermitAll`() {
        val code = """
            import javax.ws.rs.DELETE
            import javax.annotation.security.PermitAll
            class UserResource {
                @DELETE @PermitAll
                fun deleteUser(): Response = Response.noContent().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags PUT with PermitAll`() {
        val code = """
            import javax.ws.rs.PUT
            import javax.annotation.security.PermitAll
            class ConfigResource {
                @PUT @PermitAll
                fun updateConfig(dto: ConfigDto): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags PATCH with PermitAll`() {
        val code = """
            import javax.ws.rs.PATCH
            import javax.annotation.security.PermitAll
            class ProductResource {
                @PATCH @PermitAll
                fun patch(dto: PatchDto): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores GET with PermitAll — read-only public endpoint`() {
        val code = """
            import javax.ws.rs.GET
            import javax.annotation.security.PermitAll
            class HealthResource {
                @GET @PermitAll
                fun health(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores DELETE with RolesAllowed`() {
        val code = """
            import javax.ws.rs.DELETE
            import javax.annotation.security.RolesAllowed
            class AdminResource {
                @DELETE @RolesAllowed("admin")
                fun delete(): Response = Response.noContent().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores method without PermitAll`() {
        val code = """
            import javax.ws.rs.DELETE
            class UserResource {
                @DELETE
                fun delete(): Response = Response.noContent().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on Panache raw query fixture`() {
        val code = """
            fun findUsers(role: String) = User.find("role = '${'$'}role'")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusUnsafeSecurityContextRuleTest {

    private val rule = QuarkusUnsafeSecurityContextRule(Config.empty)

    @Test
    fun `flags @Context SecurityContext without role check`() {
        val code = """
            @GET
            @Path("/profile")
            fun profile(@Context ctx: SecurityContext): Response {
                return Response.ok(userService.getProfile()).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores @Context SecurityContext with isUserInRole check`() {
        val code = """
            @GET
            @Path("/admin")
            fun admin(@Context ctx: SecurityContext): Response {
                if (!ctx.isUserInRole("admin")) return Response.status(403).build()
                return Response.ok(adminService.list()).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores @Context SecurityContext with getUserPrincipal`() {
        val code = """
            @GET
            @Path("/me")
            fun me(@Context ctx: SecurityContext): Response {
                val user = ctx.getUserPrincipal()?.name ?: return Response.status(401).build()
                return Response.ok(user).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores method without SecurityContext`() {
        val code = """
            @GET
            @Path("/health")
            fun health(): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with QuarkusMissingAuth fixture`() {
        val code = """
            @POST
            @Path("/data")
            fun save(data: Data): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

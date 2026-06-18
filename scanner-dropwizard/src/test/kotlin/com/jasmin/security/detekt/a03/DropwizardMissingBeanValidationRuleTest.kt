package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardMissingBeanValidationRuleTest {

    private val rule = DropwizardMissingBeanValidationRule(Config.empty)

    @Test
    fun `flags POST parameter without @Valid`() {
        val code = """
            @POST
            fun createUser(req: CreateUserRequest): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags PUT parameter without @Valid`() {
        val code = """
            @PUT
            fun updateUser(req: UpdateUserRequest): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores POST parameter with @Valid`() {
        val code = """
            @POST
            fun createUser(@Valid req: CreateUserRequest): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores GET method (no request body)`() {
        val code = """
            @GET
            fun listUsers(): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores POST with only path params`() {
        val code = """
            @POST
            @Path("/{id}/activate")
            fun activateUser(@PathParam("id") id: Long): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a04

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusMassAssignmentRuleTest {

    private val rule = QuarkusMassAssignmentRule(Config.empty)

    @Test
    fun `flags @BeanParam on @POST method`() {
        val code = """
            @POST
            @Path("/users")
            fun create(@BeanParam user: User): Response {
                return Response.ok(userService.create(user)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags @BeanParam on @PUT method`() {
        val code = """
            @PUT
            @Path("/users/{id}")
            fun update(@PathParam("id") id: Long, @BeanParam user: User): Response {
                return Response.ok(userService.update(id, user)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores @BeanParam on @GET method`() {
        val code = """
            @GET
            @Path("/users")
            fun list(@BeanParam filter: UserFilter): List<User> {
                return userService.list(filter)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores @POST without @BeanParam`() {
        val code = """
            @POST
            @Path("/users")
            fun create(dto: CreateUserRequest): Response {
                return Response.ok(userService.create(dto)).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with QuarkusMissingAuth fixture`() {
        val code = """
            @GET
            @Path("/admin")
            fun admin(): Response = Response.ok().build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

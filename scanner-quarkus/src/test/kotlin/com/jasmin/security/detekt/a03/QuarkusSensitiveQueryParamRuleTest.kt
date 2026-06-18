package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusSensitiveQueryParamRuleTest {

    private val rule = QuarkusSensitiveQueryParamRule(Config.empty)

    @Test
    fun `flags @QueryParam with password name`() {
        val code = """
            @GET
            @Path("/auth")
            fun auth(@QueryParam("password") password: String): Response {
                return authService.authenticate(password)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags @QueryParam with token name`() {
        val code = """
            @GET
            @Path("/validate")
            fun validate(@QueryParam("token") token: String): Response {
                return tokenService.validate(token)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores @QueryParam with non-sensitive name`() {
        val code = """
            @GET
            @Path("/search")
            fun search(@QueryParam("query") q: String): List<Result> {
                return searchService.find(q)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores @PathParam with sensitive name`() {
        val code = """
            @GET
            @Path("/users/{id}")
            fun getUser(@PathParam("id") id: Long): User {
                return userService.find(id)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with PanacheRawQuery fixture`() {
        val code = """
            @GET
            fun users(): List<User> = User.list("from User")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

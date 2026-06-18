package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusPathParamInjectionRuleTest {

    private val rule = QuarkusPathParamInjectionRule(Config.empty)

    @Test
    fun `flags PathParam interpolated into Panache find`() {
        val code = """
            @GET
            @Path("/{name}")
            fun getByName(@PathParam("name") name: String): Response {
                val result = User.find("name = '${'$'}name'").list()
                return Response.ok(result).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores PathParam with positional parameter binding`() {
        val code = """
            @GET
            @Path("/{name}")
            fun getByName(@PathParam("name") name: String): Response {
                val result = User.find("name = ?1", name).list()
                return Response.ok(result).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores function without PathParam`() {
        val code = """
            @GET
            fun listAll(): Response {
                val result = User.find("active = true").list()
                return Response.ok(result).build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

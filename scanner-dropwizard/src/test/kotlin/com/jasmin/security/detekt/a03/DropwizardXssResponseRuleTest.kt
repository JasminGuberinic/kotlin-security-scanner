package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardXssResponseRuleTest {

    private val rule = DropwizardXssResponseRule(Config.empty)

    @Test
    fun `flags Produces text_html endpoint`() {
        val code = """
            @GET
            @Produces("text/html")
            fun renderPage(@QueryParam("name") name: String): Response {
                return Response.ok("<h1>Hello ${'$'}name</h1>").build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Produces TEXT_HTML constant endpoint`() {
        val code = """
            @GET
            @Produces(MediaType.TEXT_HTML)
            fun renderPage(): Response = Response.ok("<h1>Hello</h1>").build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Produces APPLICATION_JSON`() {
        val code = """
            @GET
            @Produces(MediaType.APPLICATION_JSON)
            fun getUsers(): Response = Response.ok(userService.findAll()).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores method without Produces annotation`() {
        val code = """
            @GET
            fun getUsers(): Response = Response.ok(userService.findAll()).build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

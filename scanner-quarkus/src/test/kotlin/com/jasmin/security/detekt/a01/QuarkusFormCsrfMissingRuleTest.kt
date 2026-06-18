package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusFormCsrfMissingRuleTest {

    private val rule = QuarkusFormCsrfMissingRule(Config.empty)

    @Test
    fun `flags @POST with APPLICATION_FORM_URLENCODED without CSRF header`() {
        val code = """
            @POST
            @Path("/login")
            @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
            fun login(@FormParam("username") user: String, @FormParam("password") pass: String): Response {
                return authService.login(user, pass)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags @POST with MULTIPART_FORM_DATA without CSRF header`() {
        val code = """
            @POST
            @Path("/upload")
            @Consumes(MediaType.MULTIPART_FORM_DATA)
            fun upload(@FormParam("file") file: InputStream): Response {
                return storageService.save(file)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores @POST with CSRF token header param`() {
        val code = """
            @POST
            @Path("/login")
            @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
            fun login(
                @FormParam("username") user: String,
                @HeaderParam("X-CSRF-Token") csrfToken: String,
            ): Response {
                return authService.login(user, csrfToken)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores @POST with JSON content type`() {
        val code = """
            @POST
            @Path("/login")
            @Consumes(MediaType.APPLICATION_JSON)
            fun login(creds: Credentials): Response {
                return authService.login(creds)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with QuarkusMissingAuth fixture`() {
        val code = """
            @GET
            @Path("/admin/users")
            fun listUsers(): List<User> = userService.list()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

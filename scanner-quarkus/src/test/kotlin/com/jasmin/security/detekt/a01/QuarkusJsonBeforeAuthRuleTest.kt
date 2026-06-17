package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusJsonBeforeAuthRuleTest {

    private val rule = QuarkusJsonBeforeAuthRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags Path class with method-level security only`() {
        val code = """
            @Path("/users")
            class UserResource {
                @GET
                @RolesAllowed("admin")
                fun listUsers(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Path class with Authenticated on method only`() {
        val code = """
            @Path("/api")
            class ApiResource {
                @GET
                fun publicEndpoint(): Response = Response.ok().build()

                @POST
                @Authenticated
                fun securedPost(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores Path class with class-level RolesAllowed`() {
        val code = """
            @Path("/admin")
            @RolesAllowed("admin")
            class AdminResource {
                @GET
                fun list(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Path class with no method-level security`() {
        val code = """
            @Path("/health")
            class HealthResource {
                @GET
                fun health(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-Path class`() {
        val code = """
            @Component
            class UserService {
                @RolesAllowed("admin")
                fun processUser(): Unit {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on QuarkusPermitAllSensitive fixture`() {
        val code = """
            @Path("/items")
            @RolesAllowed("user")
            class ItemResource {
                @DELETE
                @PermitAll
                fun deleteItem(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

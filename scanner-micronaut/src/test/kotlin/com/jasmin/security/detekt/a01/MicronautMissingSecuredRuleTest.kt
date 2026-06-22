package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautMissingSecuredRuleTest {

    private val rule = MicronautMissingSecuredRule(Config.empty)

    // ── Positive tests — must be flagged ─────────────────────────────────────

    @Test
    fun `flags Get endpoint without Secured`() {
        val code = """
            import io.micronaut.http.annotation.Controller
            import io.micronaut.http.annotation.Get
            @Controller("/users")
            class UserController {
                @Get
                fun list(): List<String> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Post endpoint without Secured`() {
        val code = """
            import io.micronaut.http.annotation.Controller
            import io.micronaut.http.annotation.Post
            @Controller("/users")
            class UserController {
                @Post
                fun create(dto: UserDto): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Delete endpoint without Secured`() {
        val code = """
            import io.micronaut.http.annotation.Controller
            import io.micronaut.http.annotation.Delete
            @Controller("/admin")
            class AdminController {
                @Delete("/{id}")
                fun delete(id: Long): String = "deleted"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative tests — must NOT be flagged ──────────────────────────────────

    @Test
    fun `ignores Get with Secured at method level`() {
        val code = """
            import io.micronaut.http.annotation.Controller
            import io.micronaut.http.annotation.Get
            import io.micronaut.security.annotation.Secured
            import io.micronaut.security.rules.SecurityRule
            @Controller("/users")
            class UserController {
                @Get
                @Secured(SecurityRule.IS_AUTHENTICATED)
                fun list(): List<String> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Get when class has Secured`() {
        val code = """
            import io.micronaut.http.annotation.Controller
            import io.micronaut.http.annotation.Get
            import io.micronaut.security.annotation.Secured
            import io.micronaut.security.rules.SecurityRule
            @Controller("/users")
            @Secured(SecurityRule.IS_AUTHENTICATED)
            class UserController {
                @Get
                fun list(): List<String> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Get with Secured IS_ANONYMOUS — explicitly public`() {
        val code = """
            import io.micronaut.http.annotation.Controller
            import io.micronaut.http.annotation.Get
            import io.micronaut.security.annotation.Secured
            import io.micronaut.security.rules.SecurityRule
            @Controller("/health")
            class HealthController {
                @Get
                @Secured(SecurityRule.IS_ANONYMOUS)
                fun check(): String = "ok"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores plain method without HTTP annotation`() {
        val code = """
            class UserService {
                fun findById(id: Long): String = id.toString()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation tests — no interference with other rules ────────────────────

    @Test
    fun `does not trigger on Ktor routing code`() {
        val code = """
            fun Application.configureRoutes() {
                routing {
                    get("/users") { call.respondText("ok") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on hardcoded password`() {
        val code = """
            class DbConfig {
                val password = "hardcoded123"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

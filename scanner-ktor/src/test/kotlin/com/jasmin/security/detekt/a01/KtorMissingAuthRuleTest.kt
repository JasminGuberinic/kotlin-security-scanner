package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorMissingAuthRuleTest {

    private val rule = KtorMissingAuthRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags routing block without authenticate`() {
        val code = """
            fun Application.configureRouting() {
                routing {
                    get("/users") { call.respond("ok") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags routing block with only public get endpoint`() {
        val code = """
            fun configure() {
                routing {
                    get("/health") { call.respond("UP") }
                    post("/data") { call.respond("saved") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags empty routing block`() {
        val code = """
            fun configure() {
                routing { }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores routing block with authenticate`() {
        val code = """
            routing {
                authenticate("auth-jwt") {
                    get("/users") { call.respond("ok") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores routing with mixed authenticate and public routes`() {
        val code = """
            routing {
                get("/health") { call.respond("UP") }
                authenticate("jwt") {
                    get("/secure") { call.respond("secret") }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on KtorPermissiveCors fixture`() {
        val code = """
            install(CORS) { anyHost() }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

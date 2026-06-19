package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusSystemExitRuleTest {

    private val rule = QuarkusSystemExitRule(Config.empty)

    // ── Positive tests — must be flagged ─────────────────────────────────────

    @Test
    fun `flags System exit call`() {
        val code = """
            package com.example
            class AdminResource {
                fun shutdown() {
                    System.exit(1)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Kotlin exitProcess call`() {
        val code = """
            package com.example
            import kotlin.system.exitProcess
            class SafeResource {
                fun kill() {
                    exitProcess(0)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative tests — must NOT be flagged ──────────────────────────────────

    @Test
    fun `ignores plain function named exit`() {
        val code = """
            package com.example
            class Game {
                fun exit() {
                    // Obična metoda unutar klase
                }
                fun process() {
                    exit()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation tests — no interference with other rules ────────────────────

    @Test
    fun `does not trigger on unprotected JAX-RS endpoint`() {
        val code = """
            import javax.ws.rs.GET
            class UserResource {
                @GET
                fun listUsers(): Response = Response.ok().build()
            }
        """.trimIndent()
        // Ovo treba da uhvati QuarkusMissingAuthRule, a ne naše pravilo za exit!
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on SQL string`() {
        val code = """
            class UserRepository {
                fun findAll(): List<User> {
                    val sql = "SELECT * FROM users WHERE active = true"
                    return em.createNativeQuery(sql).resultList as List<User>
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}
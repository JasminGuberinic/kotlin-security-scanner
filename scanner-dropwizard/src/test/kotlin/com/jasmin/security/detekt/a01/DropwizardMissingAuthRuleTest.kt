package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardMissingAuthRuleTest {

    private val rule = DropwizardMissingAuthRule(Config.empty)

    // ── Positive tests — must be flagged ─────────────────────────────────────

    @Test
    fun `flags GET endpoint without auth annotation`() {
        val code = """
            import javax.ws.rs.GET
            class UserResource {
                @GET
                fun getAll(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags POST endpoint without auth annotation`() {
        val code = """
            import javax.ws.rs.POST
            class UserResource {
                @POST
                fun create(dto: UserDto): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags DELETE endpoint without auth annotation`() {
        val code = """
            import javax.ws.rs.DELETE
            class UserResource {
                @DELETE
                fun delete(): Response = Response.noContent().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative tests — must NOT be flagged ──────────────────────────────────

    @Test
    fun `ignores GET endpoint with RolesAllowed`() {
        val code = """
            import javax.ws.rs.GET
            import javax.annotation.security.RolesAllowed
            class AdminResource {
                @GET
                @RolesAllowed("ADMIN")
                fun listUsers(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores POST endpoint with Auth annotation`() {
        val code = """
            import javax.ws.rs.POST
            import io.dropwizard.auth.Auth
            class UserResource {
                @POST
                fun create(@Auth user: User, dto: UserDto): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores GET endpoint with DenyAll`() {
        val code = """
            import javax.ws.rs.GET
            import javax.annotation.security.DenyAll
            class InternalResource {
                @GET
                @DenyAll
                fun secret(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores method without HTTP annotation`() {
        val code = """
            class UserService {
                fun findUser(id: Long): User = userRepo.find(id)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation tests — no interference with other rules ────────────────────

    @Test
    fun `does not trigger on SQL query string`() {
        val code = """
            class UserRepository {
                fun findAll(): List<User> {
                    val sql = "SELECT * FROM users"
                    return db.query(sql)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on cipher getInstance call`() {
        val code = """
            import javax.crypto.Cipher
            class CryptoService {
                fun encrypt(data: ByteArray): ByteArray {
                    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                    return cipher.doFinal(data)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

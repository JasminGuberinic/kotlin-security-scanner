package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusMissingAuthRuleTest {

    private val rule = QuarkusMissingAuthRule(Config.empty)

    // ── Positive tests — must be flagged ─────────────────────────────────────

    @Test
    fun `flags GET endpoint without any auth annotation`() {
        val code = """
            import javax.ws.rs.GET
            class UserResource {
                @GET
                fun listUsers(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags POST endpoint without any auth annotation`() {
        val code = """
            import javax.ws.rs.POST
            class OrderResource {
                @POST
                fun createOrder(dto: OrderDto): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags DELETE endpoint without any auth annotation`() {
        val code = """
            import javax.ws.rs.DELETE
            class AdminResource {
                @DELETE
                fun deleteUser(): Response = Response.noContent().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative tests — must NOT be flagged ──────────────────────────────────

    @Test
    fun `ignores GET with RolesAllowed`() {
        val code = """
            import javax.ws.rs.GET
            import javax.annotation.security.RolesAllowed
            class UserResource {
                @GET
                @RolesAllowed("user")
                fun listUsers(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores GET with Quarkus Authenticated`() {
        val code = """
            import javax.ws.rs.GET
            import io.quarkus.security.Authenticated
            class ProfileResource {
                @GET
                @Authenticated
                fun profile(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores GET with PermitAll — explicitly public`() {
        val code = """
            import javax.ws.rs.GET
            import javax.annotation.security.PermitAll
            class HealthResource {
                @GET
                @PermitAll
                fun health(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores GET with DenyAll`() {
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
    fun `ignores plain method without HTTP annotation`() {
        val code = """
            class UserService {
                fun findById(id: Long): User = repo.find(id)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation tests — no interference with other rules ────────────────────

    @Test
    fun `does not trigger on ConfigProperty with hardcoded secret`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class ApiClient {
                @ConfigProperty(name = "api.secret", defaultValue = "hardcoded")
                lateinit var apiSecret: String
            }
        """.trimIndent()
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

    @Test
    fun `does not trigger on weak cipher`() {
        val code = """
            import javax.crypto.Cipher
            class CryptoUtil {
                fun encryptLegacy(data: ByteArray): ByteArray {
                    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
                    return cipher.doFinal(data)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

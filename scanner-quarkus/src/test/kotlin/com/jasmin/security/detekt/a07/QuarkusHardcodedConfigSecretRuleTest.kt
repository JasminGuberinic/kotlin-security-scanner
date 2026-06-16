package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusHardcodedConfigSecretRuleTest {

    private val rule = QuarkusHardcodedConfigSecretRule(Config.empty)

    // ── Positive tests — must be flagged ─────────────────────────────────────

    @Test
    fun `flags ConfigProperty with password key and hardcoded default`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class DbConfig {
                @ConfigProperty(name = "db.password", defaultValue = "admin123")
                lateinit var password: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ConfigProperty with secret key and hardcoded default`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class ApiConfig {
                @ConfigProperty(name = "api.secret", defaultValue = "s3cr3t")
                lateinit var apiSecret: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ConfigProperty with token key and hardcoded default`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class AuthConfig {
                @ConfigProperty(name = "jwt.token.signing.key", defaultValue = "supersecretkey")
                lateinit var signingKey: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ConfigProperty with api key key and hardcoded default`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class PaymentConfig {
                @ConfigProperty(name = "stripe.apikey", defaultValue = "sk_test_hardcoded")
                lateinit var stripeKey: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative tests — must NOT be flagged ──────────────────────────────────

    @Test
    fun `ignores ConfigProperty with credential key but no defaultValue`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class DbConfig {
                @ConfigProperty(name = "db.password")
                lateinit var password: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores ConfigProperty with credential key and empty defaultValue`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class DbConfig {
                @ConfigProperty(name = "db.password", defaultValue = "")
                lateinit var password: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores ConfigProperty with non-credential key and defaultValue`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class AppConfig {
                @ConfigProperty(name = "app.name", defaultValue = "my-service")
                lateinit var appName: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores ConfigProperty with credential key and changeme placeholder`() {
        val code = """
            import org.eclipse.microprofile.config.inject.ConfigProperty
            class DbConfig {
                @ConfigProperty(name = "db.password", defaultValue = "changeme")
                lateinit var password: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores property without ConfigProperty annotation`() {
        val code = """
            class DbConfig {
                lateinit var password: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation tests — no interference with other rules ────────────────────

    @Test
    fun `does not trigger on GET endpoint without auth`() {
        val code = """
            import javax.ws.rs.GET
            class UserResource {
                @GET
                fun listUsers(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on hardcoded password variable`() {
        val code = """
            class AuthService {
                val dbPassword = "admin123"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on SQL string`() {
        val code = """
            class UserRepository {
                fun findByName(name: String): List<User> {
                    val q = "SELECT * FROM users WHERE name = " + name
                    return db.query(q)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecureTlsProtocolRuleTest {

    private val rule = InsecureTlsProtocolRule(Config.empty)

    // ── Positive tests — must be flagged ─────────────────────────────────────

    @Test
    fun `flags setSupportedProtocols with TLSv1 0`() {
        val code = """
            class TlsConfig {
                fun configure() {
                    config.setSupportedProtocols("TLSv1.0")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setSupportedProtocols with TLSv1 1`() {
        val code = """
            class TlsConfig {
                fun configure() {
                    config.setSupportedProtocols("TLSv1.1")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setSslProtocol with SSLv3`() {
        val code = """
            class TlsConfig {
                fun configure() {
                    config.setSslProtocol("SSLv3")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setEnabledProtocols with TLSv1 bare`() {
        val code = """
            class TlsConfig {
                fun configure() {
                    engine.setEnabledProtocols("TLSv1")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SSLv2Hello`() {
        val code = """
            class TlsConfig {
                fun configure() {
                    config.setSupportedProtocols("SSLv2Hello")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative tests — must NOT be flagged ──────────────────────────────────

    @Test
    fun `ignores TLSv1 2`() {
        val code = """
            class TlsConfig {
                fun configure() {
                    config.setSupportedProtocols("TLSv1.2")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores TLSv1 3`() {
        val code = """
            class TlsConfig {
                fun configure() {
                    config.setSupportedProtocols("TLSv1.3")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated setter`() {
        val code = """
            class TlsConfig {
                fun configure() {
                    config.setKeyStorePath("/etc/certs/server.jks")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores interpolated protocol string`() {
        val code = """
            class TlsConfig {
                fun configure(proto: String) {
                    config.setSupportedProtocols(proto)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation tests — no interference with other rules ────────────────────

    @Test
    fun `does not trigger on JAX-RS endpoint without auth`() {
        val code = """
            import javax.ws.rs.GET
            class UserResource {
                @GET
                fun list(): Response = Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on SQL string`() {
        val code = """
            class UserRepository {
                fun findAll(): List<User> {
                    val q = "SELECT * FROM users WHERE id = " + id
                    return db.query(q)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

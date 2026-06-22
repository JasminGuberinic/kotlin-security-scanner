package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class CorsWildcardOriginsRuleTest {

    private val rule = CorsWildcardOriginsRule(Config.empty)

    @Test
    fun `flags allowedOrigins with wildcard`() {
        val code = """
            class CorsConfig {
                fun configure() = allowedOrigins("*")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags addAllowedOrigin with wildcard`() {
        val code = """
            class CorsConfig {
                fun configure(cfg: CorsConfiguration) {
                    cfg.addAllowedOrigin("*")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags allowedOriginsRegex with wildcard`() {
        val code = """
            class CorsConfig {
                fun configure() = allowedOriginsRegex("*")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags chained allowedOrigins call`() {
        val code = """
            class CorsConfig {
                fun configure(corsConfig: CorsOriginConfiguration) {
                    corsConfig.allowedOrigins("*")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores allowedOrigins with specific domain`() {
        val code = """
            class CorsConfig {
                fun configure() = allowedOrigins("https://app.example.com")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores allowedOrigins with multiple specific domains`() {
        val code = """
            class CorsConfig {
                fun configure() = allowedOrigins("https://app.example.com", "https://admin.example.com")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores allowedOrigins with variable`() {
        val code = """
            class CorsConfig {
                val origin = System.getenv("ALLOWED_ORIGIN")
                fun configure() = allowedOrigins(origin)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorWeakJwtSecretRuleTest {

    private val rule = KtorWeakJwtSecretRule(Config.empty)

    @Test
    fun `flags HMAC256 with string literal`() {
        val code = """
            fun configure() {
                JWT.require(Algorithm.HMAC256("my-super-secret-key"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags HMAC512 with string literal`() {
        val code = """
            fun configure() {
                JWT.require(Algorithm.HMAC512("another-secret"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores HMAC256 with environment variable`() {
        val code = """
            val secret = System.getenv("JWT_SECRET") ?: error("JWT_SECRET not set")
            JWT.require(Algorithm.HMAC256(secret))
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with basic auth code`() {
        val code = """
            install(Authentication) {
                basic("auth") {
                    validate { credentials ->
                        if (credentials.password == "correct") UserIdPrincipal(credentials.name) else null
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

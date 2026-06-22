package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautHardcodedSecretRuleTest {

    private val rule = MicronautHardcodedSecretRule(Config.empty)

    private val S = "${'$'}"

    @Test
    fun `flags Value with hardcoded default for jwt secret`() {
        val code = """
            import io.micronaut.context.annotation.Value
            class JwtConfig {
                @Value("${S}{jwt.secret:my-hardcoded-secret-key}")
                lateinit var jwtSecret: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Value with hardcoded default for password property`() {
        val code = """
            import io.micronaut.context.annotation.Value
            class DbConfig {
                @Value("${S}{datasource.password:admin123}")
                lateinit var password: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Value with hardcoded default for api-key`() {
        val code = """
            import io.micronaut.context.annotation.Value
            class ApiConfig {
                @Value("${S}{service.api-key:default-key-value}")
                lateinit var apiKey: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Value without default — safe fail-fast pattern`() {
        val code = """
            import io.micronaut.context.annotation.Value
            class JwtConfig {
                @Value("${S}{jwt.secret}")
                lateinit var jwtSecret: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Value with empty default`() {
        val code = """
            import io.micronaut.context.annotation.Value
            class Config {
                @Value("${S}{app.name:}")
                lateinit var appName: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Value with non-sensitive property name`() {
        val code = """
            import io.micronaut.context.annotation.Value
            class Config {
                @Value("${S}{app.name:MyApp}")
                lateinit var appName: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not trigger on CORS wildcard code`() {
        val code = """
            class CorsConfig {
                fun configure() { allowedOrigins("https://app.example.com") }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

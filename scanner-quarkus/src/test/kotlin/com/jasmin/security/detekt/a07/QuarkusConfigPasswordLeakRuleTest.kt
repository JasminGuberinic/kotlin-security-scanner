package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusConfigPasswordLeakRuleTest {

    private val rule = QuarkusConfigPasswordLeakRule(Config.empty)

    @Test
    fun `flags ConfigProperty with password name and defaultValue`() {
        val code = """
            @ApplicationScoped
            class Config {
                @ConfigProperty(name = "app.db.password", defaultValue = "changeme")
                lateinit var password: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ConfigProperty with secret in name and defaultValue`() {
        val code = """
            @ApplicationScoped
            class Config {
                @ConfigProperty(name = "app.api-key", defaultValue = "hardcoded-api-key")
                lateinit var apiKey: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores ConfigProperty with sensitive name but no defaultValue`() {
        val code = """
            @ApplicationScoped
            class Config {
                @ConfigProperty(name = "app.db.password")
                lateinit var password: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores ConfigProperty with non-sensitive name and defaultValue`() {
        val code = """
            @ApplicationScoped
            class Config {
                @ConfigProperty(name = "app.greeting", defaultValue = "Hello")
                lateinit var greeting: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with hardcoded config secret code`() {
        val code = """
            @ApplicationScoped
            class AppConfig {
                @ConfigProperty(name = "app.host", defaultValue = "localhost")
                lateinit var host: String
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

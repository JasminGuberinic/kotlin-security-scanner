package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class SecurityLoggingVerboseRuleTest {

    private val rule = SecurityLoggingVerboseRule(Config.empty)

    @Test
    fun `flags Spring Security DEBUG logging`() {
        val props = Properties().also {
            it["logging.level.org.springframework.security"] = "DEBUG"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags Spring Security TRACE logging`() {
        val props = Properties().also {
            it["logging.level.org.springframework.security"] = "TRACE"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags Spring Security oauth2 DEBUG logging`() {
        val props = Properties().also {
            it["logging.level.org.springframework.security.oauth2"] = "DEBUG"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores DEBUG logging in dev profile`() {
        val props = Properties().also {
            it["%dev.logging.level.org.springframework.security"] = "DEBUG"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores DEBUG logging in test profile`() {
        val props = Properties().also {
            it["%test.logging.level.org.springframework.security"] = "DEBUG"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores INFO level Spring Security logging`() {
        val props = Properties().also {
            it["logging.level.org.springframework.security"] = "INFO"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated DEBUG logging`() {
        val props = Properties().also {
            it["logging.level.com.example.myapp"] = "DEBUG"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

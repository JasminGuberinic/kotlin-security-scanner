package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class H2ConsoleEnabledRuleTest {

    private val rule = H2ConsoleEnabledRule(Config.empty)

    @Test
    fun `flags h2 console enabled without profile`() {
        val props = Properties().also {
            it["spring.h2.console.enabled"] = "true"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags h2 console enabled in prod profile`() {
        val props = Properties().also {
            it["%prod.spring.h2.console.enabled"] = "true"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores h2 console enabled in dev profile`() {
        val props = Properties().also {
            it["%dev.spring.h2.console.enabled"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores h2 console enabled in test profile`() {
        val props = Properties().also {
            it["%test.spring.h2.console.enabled"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores h2 console disabled`() {
        val props = Properties().also {
            it["spring.h2.console.enabled"] = "false"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated properties`() {
        val props = Properties().also {
            it["spring.datasource.url"] = "jdbc:h2:mem:testdb"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

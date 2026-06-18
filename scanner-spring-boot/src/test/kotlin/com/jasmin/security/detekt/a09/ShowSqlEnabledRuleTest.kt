package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class ShowSqlEnabledRuleTest {

    private val rule = ShowSqlEnabledRule(Config.empty)

    @Test
    fun `flags show-sql true without profile`() {
        val props = Properties().also {
            it["spring.jpa.show-sql"] = "true"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hibernate SQL logging at DEBUG level`() {
        val props = Properties().also {
            it["logging.level.org.hibernate.SQL"] = "DEBUG"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hibernate SQL logging at TRACE level`() {
        val props = Properties().also {
            it["logging.level.org.hibernate.SQL"] = "TRACE"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores show-sql true in dev profile`() {
        val props = Properties().also {
            it["%dev.spring.jpa.show-sql"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores show-sql false`() {
        val props = Properties().also {
            it["spring.jpa.show-sql"] = "false"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated logging properties`() {
        val props = Properties().also {
            it["logging.level.com.myapp"] = "DEBUG"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

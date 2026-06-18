package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class SpringActuatorShutdownEnabledRuleTest {

    private val rule = SpringActuatorShutdownEnabledRule(Config.empty)

    @Test
    fun `flags shutdown endpoint enabled`() {
        val props = Properties().also {
            it["management.endpoint.shutdown.enabled"] = "true"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags shutdown in exposure include list`() {
        val props = Properties().also {
            it["management.endpoints.web.exposure.include"] = "health,info,shutdown"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags both shutdown enabled and exposed`() {
        val props = Properties().also {
            it["management.endpoint.shutdown.enabled"] = "true"
            it["management.endpoints.web.exposure.include"] = "shutdown"
        }
        assertThat(rule.scanProperties(props)).hasSize(2)
    }

    @Test
    fun `ignores shutdown disabled`() {
        val props = Properties().also {
            it["management.endpoint.shutdown.enabled"] = "false"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores exposure list without shutdown`() {
        val props = Properties().also {
            it["management.endpoints.web.exposure.include"] = "health,info"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated management properties`() {
        val props = Properties().also {
            it["management.endpoint.health.enabled"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

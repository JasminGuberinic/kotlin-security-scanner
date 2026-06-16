package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class InsecureActuatorExposureRuleTest {

    private val rule = InsecureActuatorExposureRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags wildcard actuator exposure`() {
        val props = Properties().also {
            it["management.endpoints.web.exposure.include"] = "*"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags management security disabled`() {
        val props = Properties().also {
            it["management.security.enabled"] = "false"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags both wildcard and disabled security`() {
        val props = Properties().also {
            it["management.endpoints.web.exposure.include"] = "*"
            it["management.security.enabled"] = "false"
        }
        assertThat(rule.scanProperties(props)).hasSize(2)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores restricted endpoint exposure`() {
        val props = Properties().also {
            it["management.endpoints.web.exposure.include"] = "health,info"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores security enabled`() {
        val props = Properties().also {
            it["management.security.enabled"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated properties`() {
        val props = Properties().also {
            it["spring.datasource.url"] = "jdbc:postgresql://localhost/db"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

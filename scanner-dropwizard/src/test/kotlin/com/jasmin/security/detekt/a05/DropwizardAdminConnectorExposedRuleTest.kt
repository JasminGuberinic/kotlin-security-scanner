package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class DropwizardAdminConnectorExposedRuleTest {

    private val rule = DropwizardAdminConnectorExposedRule(Config.empty)

    @Test
    fun `flags admin connector bound to 0_0_0_0`() {
        val props = Properties().also {
            it["server.adminConnectors[0].bindHost"] = "0.0.0.0"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores admin connector bound to localhost`() {
        val props = Properties().also {
            it["server.adminConnectors[0].bindHost"] = "127.0.0.1"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores application connector on 0_0_0_0`() {
        val props = Properties().also {
            it["server.applicationConnectors[0].bindHost"] = "0.0.0.0"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

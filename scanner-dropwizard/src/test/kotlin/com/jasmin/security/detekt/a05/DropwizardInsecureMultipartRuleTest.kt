package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class DropwizardInsecureMultipartRuleTest {

    private val rule = DropwizardInsecureMultipartRule(Config.empty)

    @Test
    fun `flags very large maxRequestEntitySize in MiB`() {
        val props = Properties().also {
            it["server.maxRequestEntitySize"] = "500MiB"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags very large maxRequestEntitySize in GiB`() {
        val props = Properties().also {
            it["server.maxRequestEntitySize"] = "2GiB"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores reasonable maxRequestEntitySize`() {
        val props = Properties().also {
            it["server.maxRequestEntitySize"] = "10MiB"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated server properties`() {
        val props = Properties().also {
            it["server.applicationConnectors[0].port"] = "8080"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

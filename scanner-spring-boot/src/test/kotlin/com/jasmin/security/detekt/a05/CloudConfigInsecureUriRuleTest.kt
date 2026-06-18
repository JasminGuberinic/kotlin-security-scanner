package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class CloudConfigInsecureUriRuleTest {

    private val rule = CloudConfigInsecureUriRule(Config.empty)

    @Test
    fun `flags cloud config uri with http`() {
        val props = Properties().also {
            it["spring.cloud.config.uri"] = "http://config-server:8888"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags cloud config server git uri with http`() {
        val props = Properties().also {
            it["spring.cloud.config.server.git.uri"] = "http://git-server/config-repo"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores cloud config uri with https`() {
        val props = Properties().also {
            it["spring.cloud.config.uri"] = "https://config-server:8888"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated spring cloud properties`() {
        val props = Properties().also {
            it["spring.cloud.gateway.routes[0].id"] = "my-route"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

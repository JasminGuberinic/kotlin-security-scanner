package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class KafkaTrustedPackagesWildcardRuleTest {

    private val rule = KafkaTrustedPackagesWildcardRule(Config.empty)

    @Test
    fun `flags consumer trusted packages wildcard`() {
        val props = Properties().also {
            it["spring.kafka.consumer.properties.spring.json.trusted.packages"] = "*"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags any key containing trusted packages set to wildcard`() {
        val props = Properties().also {
            it["spring.json.trusted.packages"] = "*"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores trusted packages with specific package list`() {
        val props = Properties().also {
            it["spring.kafka.consumer.properties.spring.json.trusted.packages"] = "com.myapp.dto,com.myapp.event"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated kafka properties`() {
        val props = Properties().also {
            it["spring.kafka.bootstrap-servers"] = "localhost:9092"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class KafkaInsecureProtocolRuleTest {

    private val rule = KafkaInsecureProtocolRule(Config.empty)

    @Test
    fun `flags spring kafka security protocol set to PLAINTEXT`() {
        val props = Properties().also {
            it["spring.kafka.security.protocol"] = "PLAINTEXT"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags consumer security protocol set to PLAINTEXT`() {
        val props = Properties().also {
            it["spring.kafka.consumer.security.protocol"] = "PLAINTEXT"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags producer security protocol set to PLAINTEXT`() {
        val props = Properties().also {
            it["spring.kafka.producer.security.protocol"] = "PLAINTEXT"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores SASL_SSL protocol`() {
        val props = Properties().also {
            it["spring.kafka.security.protocol"] = "SASL_SSL"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores SSL protocol`() {
        val props = Properties().also {
            it["spring.kafka.security.protocol"] = "SSL"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated properties`() {
        val props = Properties().also {
            it["spring.kafka.bootstrap-servers"] = "localhost:9092"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

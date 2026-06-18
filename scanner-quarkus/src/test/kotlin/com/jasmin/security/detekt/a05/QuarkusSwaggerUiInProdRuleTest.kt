package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusSwaggerUiInProdRuleTest {

    private val rule = QuarkusSwaggerUiInProdRule(Config.empty)

    @Test
    fun `flags swagger-ui always-include without profile prefix`() {
        val props = Properties().also {
            it["quarkus.swagger-ui.always-include"] = "true"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores swagger-ui always-include in dev profile`() {
        val props = Properties().also {
            it["%dev.quarkus.swagger-ui.always-include"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores swagger-ui always-include set to false`() {
        val props = Properties().also {
            it["quarkus.swagger-ui.always-include"] = "false"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated quarkus properties`() {
        val props = Properties().also {
            it["quarkus.http.port"] = "8080"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

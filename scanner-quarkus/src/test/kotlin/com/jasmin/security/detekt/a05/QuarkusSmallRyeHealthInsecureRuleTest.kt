package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusSmallRyeHealthInsecureRuleTest {

    private val rule = QuarkusSmallRyeHealthInsecureRule(Config.empty)

    @Test
    fun `flags SmallRye Health UI enabled without profile prefix`() {
        val props = Properties().also {
            it["quarkus.smallrye-health.ui.enable"] = "true"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores SmallRye Health UI enabled in dev profile`() {
        val props = Properties().also {
            it["%dev.quarkus.smallrye-health.ui.enable"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores SmallRye Health UI enabled in test profile`() {
        val props = Properties().also {
            it["%test.quarkus.smallrye-health.ui.enable"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores SmallRye Health UI disabled`() {
        val props = Properties().also {
            it["quarkus.smallrye-health.ui.enable"] = "false"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusMultipartInsecureRuleTest {

    private val rule = QuarkusMultipartInsecureRule(Config.empty)

    @Test
    fun `flags very large max-body-size in megabytes`() {
        val props = Properties().also {
            it["quarkus.http.limits.max-body-size"] = "500M"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags very large max-body-size in gigabytes`() {
        val props = Properties().also {
            it["quarkus.http.limits.max-body-size"] = "2G"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores reasonable max-body-size`() {
        val props = Properties().also {
            it["quarkus.http.limits.max-body-size"] = "10M"
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

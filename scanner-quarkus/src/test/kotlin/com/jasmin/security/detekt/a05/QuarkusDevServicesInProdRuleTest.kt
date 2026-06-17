package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusDevServicesInProdRuleTest {

    private val rule = QuarkusDevServicesInProdRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags dev services enabled in prod profile`() {
        val props = Properties().also { it["%prod.quarkus.devservices.enabled"] = "true" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags dev services enabled without profile`() {
        val props = Properties().also { it["quarkus.devservices.enabled"] = "true" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags both keys when both set to true`() {
        val props = Properties().also {
            it["%prod.quarkus.devservices.enabled"] = "true"
            it["quarkus.devservices.enabled"] = "true"
        }
        assertThat(rule.scanProperties(props)).hasSize(2)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores dev services explicitly disabled in prod`() {
        val props = Properties().also { it["%prod.quarkus.devservices.enabled"] = "false" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated properties`() {
        val props = Properties().also { it["quarkus.http.port"] = "8080" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

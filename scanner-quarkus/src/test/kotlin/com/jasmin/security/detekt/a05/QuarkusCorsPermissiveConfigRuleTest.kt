package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusCorsPermissiveConfigRuleTest {

    private val rule = QuarkusCorsPermissiveConfigRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags wildcard cors origins`() {
        val props = Properties().also { it["quarkus.http.cors.origins"] = "*" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags regex wildcard cors origins`() {
        val props = Properties().also { it["quarkus.http.cors.origins"] = ".*" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores specific origin`() {
        val props = Properties().also { it["quarkus.http.cors.origins"] = "https://api.example.com" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores cors feature flag without origins`() {
        val props = Properties().also { it["quarkus.http.cors"] = "false" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated properties`() {
        val props = Properties().also { it["quarkus.http.port"] = "8080" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

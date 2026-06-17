package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusSmallryeJwtInsecureRuleTest {

    private val rule = QuarkusSmallryeJwtInsecureRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags JWT algorithm none lowercase`() {
        val props = Properties().also { it["mp.jwt.verify.algorithm"] = "none" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags JWT algorithm NONE uppercase`() {
        val props = Properties().also { it["mp.jwt.verify.algorithm"] = "NONE" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded JWT secret value`() {
        val props = Properties().also { it["mp.jwt.verify.secret.value"] = "my-secret-key-12345" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores RS256 algorithm`() {
        val props = Properties().also { it["mp.jwt.verify.algorithm"] = "RS256" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores JWT secret from env var`() {
        val props = Properties().also { it["mp.jwt.verify.secret.value"] = "\${JWT_SECRET}" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated MicroProfile properties`() {
        val props = Properties().also { it["mp.jwt.verify.issuer"] = "https://example.com" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

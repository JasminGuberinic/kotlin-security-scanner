package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class InsecureSmtpConfigRuleTest {

    private val rule = InsecureSmtpConfigRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags starttls disabled`() {
        val props = Properties().also {
            it["spring.mail.properties.mail.smtp.starttls.enable"] = "false"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags ssl disabled`() {
        val props = Properties().also {
            it["spring.mail.properties.mail.smtp.ssl.enable"] = "false"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags both starttls and ssl disabled`() {
        val props = Properties().also {
            it["spring.mail.properties.mail.smtp.starttls.enable"] = "false"
            it["spring.mail.properties.mail.smtp.ssl.enable"] = "false"
        }
        assertThat(rule.scanProperties(props)).hasSize(2)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores starttls enabled`() {
        val props = Properties().also {
            it["spring.mail.properties.mail.smtp.starttls.enable"] = "true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated properties`() {
        val props = Properties().also {
            it["spring.datasource.url"] = "jdbc:postgresql://localhost/db"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

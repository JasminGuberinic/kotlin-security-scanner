package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class OAuth2ClientSecretInPropertiesRuleTest {

    private val rule = OAuth2ClientSecretInPropertiesRule(Config.empty)

    @Test
    fun `flags hardcoded oauth2 client-secret`() {
        val props = Properties().also {
            it["spring.security.oauth2.client.registration.google.client-secret"] = "hardcoded-secret-value"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded oauth2 client_secret (underscore variant)`() {
        val props = Properties().also {
            it["spring.security.oauth2.client.registration.github.client_secret"] = "ghp_actualSecret"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores environment variable placeholder`() {
        val props = Properties().also {
            it["spring.security.oauth2.client.registration.google.client-secret"] = "\${GOOGLE_CLIENT_SECRET}"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated oauth2 property`() {
        val props = Properties().also {
            it["spring.security.oauth2.client.registration.google.client-id"] = "my-client-id"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusOidcInsecureConfigRuleTest {

    private val rule = QuarkusOidcInsecureConfigRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags TLS verification disabled`() {
        val props = Properties().also {
            it["quarkus.oidc.tls.verification"] = "none"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded oidc client secret`() {
        val props = Properties().also {
            it["quarkus.oidc.credentials.secret"] = "my-hardcoded-client-secret"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags both TLS disabled and hardcoded secret`() {
        val props = Properties().also {
            it["quarkus.oidc.tls.verification"] = "none"
            it["quarkus.oidc.credentials.secret"] = "my-hardcoded-client-secret"
        }
        assertThat(rule.scanProperties(props)).hasSize(2)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores TLS verification enabled`() {
        val props = Properties().also {
            it["quarkus.oidc.tls.verification"] = "certificate"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores oidc secret from env var`() {
        val props = Properties().also {
            it["quarkus.oidc.credentials.secret"] = "\${OIDC_CLIENT_SECRET}"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated properties`() {
        val props = Properties().also {
            it["quarkus.oidc.auth-server-url"] = "https://accounts.google.com"
            it["quarkus.oidc.client-id"] = "my-app"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

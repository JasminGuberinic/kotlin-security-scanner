package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusBuildTimeSecretLeakRuleTest {

    private val rule = QuarkusBuildTimeSecretLeakRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags hardcoded datasource password`() {
        val props = Properties().also {
            it["quarkus.datasource.password"] = "mysupersecretpassword"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded api key`() {
        val props = Properties().also {
            it["app.integration.apikey"] = "abc123secretkey"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded token`() {
        val props = Properties().also {
            it["quarkus.oidc.credentials.secret"] = "hard-coded-client-secret"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded api-key with dash`() {
        val props = Properties().also {
            it["app.integration.api-key"] = "abc123secretkey"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores oidc auth-server-url (contains auth)`() {
        val props = Properties().also {
            it["quarkus.oidc.auth-server-url"] = "https://idp.example.com/realms/app"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores oidc token-path (contains token)`() {
        val props = Properties().also {
            it["quarkus.oidc.token-path"] = "/protocol/openid-connect/token"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores env var reference`() {
        val props = Properties().also {
            it["quarkus.datasource.password"] = "\${DB_PASSWORD}"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores changeme placeholder`() {
        val props = Properties().also {
            it["app.secret"] = "changeme"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated properties`() {
        val props = Properties().also {
            it["quarkus.datasource.jdbc.url"] = "jdbc:postgresql://localhost/db"
            it["quarkus.http.port"] = "8080"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

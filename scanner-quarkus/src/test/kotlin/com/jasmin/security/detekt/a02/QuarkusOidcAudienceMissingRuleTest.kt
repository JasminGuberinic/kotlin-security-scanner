package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusOidcAudienceMissingRuleTest {

    private val rule = QuarkusOidcAudienceMissingRule(Config.empty)

    @Test
    fun `flags OIDC configured without token audience`() {
        val props = Properties().also {
            it["quarkus.oidc.auth-server-url"] = "https://keycloak/auth/realms/myrealm"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores OIDC with token audience set`() {
        val props = Properties().also {
            it["quarkus.oidc.auth-server-url"] = "https://keycloak/auth/realms/myrealm"
            it["quarkus.oidc.token.audience"] = "my-service"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores properties without OIDC`() {
        val props = Properties().also {
            it["quarkus.datasource.db-kind"] = "postgresql"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class JwtSecretInPropertiesRuleTest {

    private val rule = JwtSecretInPropertiesRule(Config.empty)

    @Test
    fun `flags hardcoded jwt secret`() {
        val props = Properties().also {
            it["spring.security.oauth2.resourceserver.jwt.secret"] = "mySuperSecretKey123"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded opaque token client secret`() {
        val props = Properties().also {
            it["spring.security.oauth2.resourceserver.opaquetoken.client-secret"] = "hardcodedClientSecret"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores environment variable placeholder`() {
        val props = Properties().also {
            it["spring.security.oauth2.resourceserver.jwt.secret"] = "\${JWT_SECRET}"
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

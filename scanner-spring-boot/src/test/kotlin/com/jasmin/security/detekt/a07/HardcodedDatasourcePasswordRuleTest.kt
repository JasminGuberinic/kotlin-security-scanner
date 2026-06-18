package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class HardcodedDatasourcePasswordRuleTest {

    private val rule = HardcodedDatasourcePasswordRule(Config.empty)

    @Test
    fun `flags hardcoded datasource password`() {
        val props = Properties().also {
            it["spring.datasource.password"] = "mySecretPass123"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded hikari password`() {
        val props = Properties().also {
            it["spring.datasource.hikari.password"] = "hikariPass"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags hardcoded r2dbc password`() {
        val props = Properties().also {
            it["spring.r2dbc.password"] = "r2dbcPass"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores environment variable placeholder`() {
        val props = Properties().also {
            it["spring.datasource.password"] = "\${DB_PASSWORD}"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores empty password (used with local dev H2)`() {
        val props = Properties().also {
            it["spring.datasource.password"] = ""
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated datasource property`() {
        val props = Properties().also {
            it["spring.datasource.url"] = "jdbc:postgresql://localhost/mydb"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

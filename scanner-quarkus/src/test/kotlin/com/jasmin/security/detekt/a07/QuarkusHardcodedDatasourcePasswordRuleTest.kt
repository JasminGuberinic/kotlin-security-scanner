package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusHardcodedDatasourcePasswordRuleTest {

    private val rule = QuarkusHardcodedDatasourcePasswordRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags hardcoded datasource password`() {
        val props = Properties().also { it["quarkus.datasource.password"] = "superSecret123" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags simple string password`() {
        val props = Properties().also { it["quarkus.datasource.password"] = "password" }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores env var reference`() {
        val props = Properties().also { it["quarkus.datasource.password"] = "\${DB_PASSWORD}" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores empty password`() {
        val props = Properties().also { it["quarkus.datasource.password"] = "" }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated datasource properties`() {
        val props = Properties().also {
            it["quarkus.datasource.url"] = "jdbc:postgresql://localhost:5432/mydb"
            it["quarkus.datasource.username"] = "myuser"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

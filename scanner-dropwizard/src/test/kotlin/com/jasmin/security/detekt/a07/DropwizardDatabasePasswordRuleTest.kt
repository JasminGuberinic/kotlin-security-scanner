package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class DropwizardDatabasePasswordRuleTest {

    private val rule = DropwizardDatabasePasswordRule(Config.empty)

    @Test
    fun `flags hardcoded database password`() {
        val props = Properties().also {
            it["database.password"] = "myS3cretPass"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores environment variable placeholder`() {
        val props = Properties().also {
            it["database.password"] = "\${DB_PASSWORD}"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores empty password`() {
        val props = Properties().also {
            it["database.password"] = ""
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated database properties`() {
        val props = Properties().also {
            it["database.url"] = "jdbc:postgresql://localhost/mydb"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores non-secret database user`() {
        // database.user is a username, not a credential — must not be flagged
        val props = Properties().also {
            it["database.user"] = "app_user"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

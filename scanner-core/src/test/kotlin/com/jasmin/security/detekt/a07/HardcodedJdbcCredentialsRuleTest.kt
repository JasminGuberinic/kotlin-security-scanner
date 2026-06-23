package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HardcodedJdbcCredentialsRuleTest {

    private val rule = HardcodedJdbcCredentialsRule(Config.empty)

    @Test
    fun `flags credentials embedded as user colon pass at host`() {
        val code = """
            val url = "jdbc:postgresql://admin:s3cr3t@db.internal:5432/app"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags a password query parameter`() {
        val code = """
            val url = "jdbc:mysql://db/app?user=root&password=hunter2"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a JDBC url without credentials`() {
        val code = """
            val url = "jdbc:postgresql://db.internal:5432/app"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores a non-JDBC url with an at sign`() {
        val code = """
            val email = "mailto:admin:note@example.com"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

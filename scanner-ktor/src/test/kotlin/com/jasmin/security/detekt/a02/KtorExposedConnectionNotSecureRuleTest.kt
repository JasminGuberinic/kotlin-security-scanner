package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorExposedConnectionNotSecureRuleTest {

    private val rule = KtorExposedConnectionNotSecureRule(Config.empty)

    @Test
    fun `flags Database connect with useSSL=false`() {
        val code = """
            fun connectDb() {
                Database.connect(
                    url = "jdbc:mysql://localhost/mydb?useSSL=false",
                    driver = "com.mysql.cj.jdbc.Driver",
                )
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Database connect with ssl=false`() {
        val code = """
            fun connectDb() {
                Database.connect("jdbc:postgresql://host/db?ssl=false", "org.postgresql.Driver")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Database connect with sslmode=disable`() {
        val code = """
            fun connectDb() {
                Database.connect("jdbc:postgresql://host/db?sslmode=disable", "org.postgresql.Driver")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Database connect with ssl enabled`() {
        val code = """
            fun connectDb() {
                Database.connect(
                    url = "jdbc:postgresql://host/db?ssl=true&sslmode=require",
                    driver = "org.postgresql.Driver",
                )
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Database connect without ssl params`() {
        val code = """
            fun connectDb() {
                Database.connect("jdbc:h2:mem:test", "org.h2.Driver")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-Database connect call`() {
        val code = """
            fun connectCache() {
                CacheClient.connect("redis://localhost:6379")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with hardcoded database password code`() {
        val code = """
            fun connectDb() {
                Database.connect(
                    url = "jdbc:postgresql://localhost/mydb",
                    driver = "org.postgresql.Driver",
                    user = "admin",
                    password = "prodDbPassword123!",
                )
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

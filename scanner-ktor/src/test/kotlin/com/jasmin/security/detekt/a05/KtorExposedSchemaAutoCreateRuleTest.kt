package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorExposedSchemaAutoCreateRuleTest {

    private val rule = KtorExposedSchemaAutoCreateRule(Config.empty)

    @Test
    fun `flags SchemaUtils create in application code`() {
        val code = """
            fun Application.configureDatabases() {
                SchemaUtils.create(Users, Orders)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SchemaUtils drop`() {
        val code = """
            fun tearDown() {
                SchemaUtils.drop(Users)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SchemaUtils createMissingTablesAndColumns`() {
        val code = """
            fun migrate() {
                SchemaUtils.createMissingTablesAndColumns(Users)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores create on non-SchemaUtils receiver`() {
        val code = """
            fun setup() {
                tableFactory.create(Users)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with insecure cookie session code`() {
        val code = """
            fun Application.configureSessions() {
                install(Sessions) {
                    cookie<UserSession>("PLAIN_SESSION")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

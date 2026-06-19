package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorExposedRawSqlConcatRuleTest {

    private val rule = KtorExposedRawSqlConcatRule(Config.empty)

    @Test
    fun `flags exec with string concatenation`() {
        val code = """
            fun findUser(id: Long) {
                transaction {
                    exec("SELECT * FROM users WHERE id = " + id)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags exec with multi-part concatenation`() {
        val code = """
            fun search(field: String, value: String) {
                transaction {
                    exec("SELECT * FROM users WHERE " + field + " = '" + value + "'")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores exec with literal string only`() {
        val code = """
            fun countActive() {
                transaction {
                    exec("SELECT count(*) FROM users WHERE active = true")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Exposed DSL select`() {
        val code = """
            fun findById(id: Long) {
                transaction {
                    Users.select { Users.id eq id }.toList()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with route param injection code`() {
        val code = """
            get("/users/{id}") {
                val id = call.parameters["id"]
                transaction {
                    exec("SELECT * FROM users WHERE id = '${'$'}id'")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

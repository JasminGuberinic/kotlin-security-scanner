package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class SqlInjectionRuleTest {

    private val rule = SqlInjectionRule()

    @Test
    fun `flags string interpolation in SELECT`() {
        val code = """
            fun find(name: String) = "SELECT * FROM users WHERE name = '${'$'}name'"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags string interpolation in DELETE`() {
        val code = """
            fun delete(id: Int) = "DELETE FROM orders WHERE id = ${'$'}id"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags string interpolation in UPDATE`() {
        val code = """
            fun update(val1: String, id: Int) = "UPDATE items SET name = '${'$'}val1' WHERE id = ${'$'}id"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags string interpolation in INSERT`() {
        val code = """
            fun insert(name: String) = "INSERT INTO users (name) VALUES ('${'$'}name')"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags string concatenation in SELECT`() {
        val code = """
            fun find(userId: String): String {
                return "SELECT * FROM users WHERE id = " + userId
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores parameterized query with colon param`() {
        val code = """
            val query = "SELECT * FROM users WHERE name = :name"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores parameterized query with question mark`() {
        val code = """
            val query = "SELECT * FROM users WHERE id = ?"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores plain string sql without variables`() {
        val code = """
            val query = "SELECT * FROM users WHERE active = true"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag hardcoded credential patterns
    @Test
    fun `does not interfere with hardcoded credential code`() {
        val code = """val dbPassword = "myS3cretPass!"""
        assertThat(rule.lint(code)).isEmpty()
    }
}

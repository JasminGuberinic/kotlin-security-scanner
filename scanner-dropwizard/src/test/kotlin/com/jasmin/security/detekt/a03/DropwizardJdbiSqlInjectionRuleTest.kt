package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardJdbiSqlInjectionRuleTest {

    private val rule = DropwizardJdbiSqlInjectionRule(Config.empty)

    @Test
    fun `flags SqlQuery with string interpolation`() {
        val code = """
            @SqlQuery("SELECT * FROM users WHERE name = '${'$'}name'")
            fun findByName(name: String): List<User>
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SqlUpdate with string interpolation`() {
        val code = """
            @SqlUpdate("UPDATE users SET active = true WHERE id = ${'$'}id")
            fun activate(id: Long)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores SqlQuery with static string literal`() {
        val code = """
            @SqlQuery("SELECT * FROM users WHERE name = :name")
            fun findByName(@Bind("name") name: String): List<User>
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores regular function without JDBI annotation`() {
        val code = """
            fun findByName(name: String): List<User> = emptyList()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

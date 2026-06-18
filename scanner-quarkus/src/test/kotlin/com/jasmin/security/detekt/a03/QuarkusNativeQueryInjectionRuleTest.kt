package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusNativeQueryInjectionRuleTest {

    private val rule = QuarkusNativeQueryInjectionRule(Config.empty)

    @Test
    fun `flags createNativeQuery with variable`() {
        val code = """
            fun findByName(name: String): List<User> {
                return em.createNativeQuery(name).resultList as List<User>
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags createNativeQuery with string interpolation`() {
        val code = """
            fun findById(id: Long): User? {
                return em.createNativeQuery("SELECT * FROM users WHERE id = ${'$'}id").singleResult as User
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores createNativeQuery with string literal`() {
        val code = """
            fun findAll(): List<User> {
                return em.createNativeQuery("SELECT * FROM users WHERE active = true").resultList as List<User>
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with Panache raw query code`() {
        val code = """
            fun findByStatus(status: String): List<Task> {
                return Task.find("status", status).list()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringDataSortInjectionRuleTest {

    private val rule = SpringDataSortInjectionRule(Config.empty)

    @Test
    fun `flags Sort_by with variable argument`() {
        val code = """
            fun findUsers(sortField: String): List<User> {
                return userRepository.findAll(Sort.by(sortField))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Sort_by with request parameter`() {
        val code = """
            @GetMapping("/users")
            fun listUsers(@RequestParam sort: String): List<User> {
                return userRepository.findAll(Sort.by(sort))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Sort_by with string literal`() {
        val code = """
            fun findUsers(): List<User> {
                return userRepository.findAll(Sort.by("name"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Sort_by with Sort_Direction (safe overload)`() {
        val code = """
            fun findUsers(): List<User> {
                return userRepository.findAll(Sort.by(Sort.Direction.ASC, "name"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with SpEL injection code`() {
        val code = """
            val parser = SpelExpressionParser()
            val expr = parser.parseExpression("'hello'")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

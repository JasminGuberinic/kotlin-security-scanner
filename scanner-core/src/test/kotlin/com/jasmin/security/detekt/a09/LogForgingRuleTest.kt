package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class LogForgingRuleTest {

    private val rule = LogForgingRule(Config.empty)

    @Test
    fun `flags request input interpolated into a log message`() {
        val code = """
            import org.slf4j.Logger
            fun handle(request: Map<String, String>, log: Logger) {
                log.info("Requested path: ${'$'}{request["path"]}")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags a simple interpolated request variable`() {
        val code = """
            import org.slf4j.Logger
            fun handle(username: String, log: Logger) {
                log.warn("login for ${'$'}username")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a parameterized log statement`() {
        val code = """
            import org.slf4j.Logger
            fun handle(request: Map<String, String>, log: Logger) {
                log.info("Requested path: {}", request["path"])
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores a static log message`() {
        val code = """
            import org.slf4j.Logger
            fun handle(log: Logger) {
                log.info("request handled successfully")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DropwizardSensitiveDataLoggingRuleTest {

    private val rule = DropwizardSensitiveDataLoggingRule(Config.empty)

    @Test
    fun `flags log statement with password keyword`() {
        val code = """
            fun authenticate(user: String, password: String) {
                logger.info("Authenticating with password: {}", password)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags log statement with token keyword`() {
        val code = """
            fun process(token: String) {
                logger.debug("Processing token: {}", token)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores log statement without sensitive keyword`() {
        val code = """
            fun process(userId: Long) {
                logger.info("Processing user: {}", userId)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-log method with sensitive keyword in string`() {
        val code = """
            fun describe(): String = "Enter your password below"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

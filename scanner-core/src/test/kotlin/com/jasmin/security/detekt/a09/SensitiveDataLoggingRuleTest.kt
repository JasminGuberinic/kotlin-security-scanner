package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.test.assertThat
import io.gitlab.arturbosch.detekt.test.lint
import org.junit.jupiter.api.Test

class SensitiveDataLoggingRuleTest {

    private val rule = SensitiveDataLoggingRule()

    @Test
    fun `flags logging password variable`() {
        val code = """
            val logger = org.slf4j.LoggerFactory.getLogger("test")
            fun login(password: String) {
                logger.info("User login with password: ${'$'}password")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags logging token variable`() {
        val code = """
            val logger = org.slf4j.LoggerFactory.getLogger("test")
            fun auth(token: String) {
                logger.debug("Received token: ${'$'}token")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags logging secret variable`() {
        val code = """
            val logger = org.slf4j.LoggerFactory.getLogger("test")
            fun setup(clientSecret: String) {
                logger.warn("Config secret=${'$'}clientSecret")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags error logging with credential`() {
        val code = """
            val logger = org.slf4j.LoggerFactory.getLogger("test")
            fun handle(apiKey: String) {
                logger.error("Failed with apiKey=${'$'}apiKey")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores logging non-sensitive data`() {
        val code = """
            val logger = org.slf4j.LoggerFactory.getLogger("test")
            fun process(userId: String) {
                logger.info("Processing request for userId=${'$'}userId")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores logging plain string without interpolation`() {
        val code = """
            val logger = org.slf4j.LoggerFactory.getLogger("test")
            fun start() {
                logger.info("Application started")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-log method calls`() {
        val code = """
            fun process(password: String) = println("password: ${'$'}password")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag path traversal patterns
    @Test
    fun `does not interfere with path traversal code`() {
        val code = """
            fun readFile(userPath: String) = java.io.File(userPath)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // Isolation: must not flag hardcoded credential patterns
    @Test
    fun `does not interfere with hardcoded credential code`() {
        val code = """val dbPassword = "hardcoded-secret""""
        assertThat(rule.lint(code)).isEmpty()
    }
}

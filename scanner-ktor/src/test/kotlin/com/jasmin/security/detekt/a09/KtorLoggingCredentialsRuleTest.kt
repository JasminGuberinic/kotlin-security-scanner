package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorLoggingCredentialsRuleTest {

    private val rule = KtorLoggingCredentialsRule(Config.empty)

    @Test
    fun `flags log statement with token keyword`() {
        val code = """
            get("/auth") {
                val token = call.request.header("Authorization")
                log.debug("Received token: ${'$'}token")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags log statement with password keyword`() {
        val code = """
            post("/login") {
                val creds = call.receive<Credentials>()
                log.info("Login attempt with password: ${'$'}{creds.password}")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores log statement without sensitive keyword`() {
        val code = """
            get("/health") {
                log.info("Health check requested by ${'$'}{call.request.host()}")
                call.respond("ok")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-log method with sensitive keyword`() {
        val code = """
            fun describe() = "Enter your password to authenticate"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

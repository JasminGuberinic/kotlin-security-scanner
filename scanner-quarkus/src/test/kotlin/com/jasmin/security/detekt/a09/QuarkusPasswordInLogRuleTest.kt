package com.jasmin.security.detekt.a09

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusPasswordInLogRuleTest {

    private val rule = QuarkusPasswordInLogRule(Config.empty)

    @Test
    fun `flags log debug with password in message`() {
        val code = """
            fun authenticate(user: String, pass: String) {
                log.debug("Authenticating with password=${'$'}pass")
                authService.login(user, pass)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags logger info with token in message`() {
        val code = """
            fun validateToken(token: String) {
                logger.info("Validating token: ${'$'}token")
                jwtService.validate(token)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores log without sensitive keyword`() {
        val code = """
            fun getUser(id: Long): User {
                log.info("Fetching user with id=${'$'}id")
                return userService.find(id)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-log method with sensitive keyword`() {
        val code = """
            fun describePolicy(): String = "Enter your password to authenticate"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with QuarkusConfigPasswordLeak fixture`() {
        val code = """
            quarkus.datasource.password=${'$'}{DB_PASSWORD}
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

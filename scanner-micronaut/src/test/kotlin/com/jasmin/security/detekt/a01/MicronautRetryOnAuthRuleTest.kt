package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautRetryOnAuthRuleTest {

    private val rule = MicronautRetryOnAuthRule(Config.empty)

    @Test
    fun `flags Retryable on authenticate method`() {
        val code = """
            import io.micronaut.retry.annotation.Retryable
            class AuthService {
                @Retryable
                fun authenticate(username: String, password: String): Boolean = false
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Retryable on login method`() {
        val code = """
            import io.micronaut.retry.annotation.Retryable
            class AuthService {
                @Retryable
                fun login(credentials: Any): String = ""
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Retryable on verifyPassword method`() {
        val code = """
            import io.micronaut.retry.annotation.Retryable
            class AuthService {
                @Retryable
                fun verifyPassword(hash: String, input: String): Boolean = false
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Retryable on non-auth method`() {
        val code = """
            import io.micronaut.retry.annotation.Retryable
            class PaymentService {
                @Retryable
                fun processPayment(amount: Double): Boolean = false
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores authenticate method without Retryable`() {
        val code = """
            class AuthService {
                fun authenticate(username: String, password: String): Boolean = false
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

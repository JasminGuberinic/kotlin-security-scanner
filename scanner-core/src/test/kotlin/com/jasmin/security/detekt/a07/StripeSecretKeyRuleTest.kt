package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class StripeSecretKeyRuleTest {

    private val rule = StripeSecretKeyRule(Config.empty)

    // The dummy tokens are assembled at runtime so this source file never contains a
    // contiguous Stripe-format literal (which GitHub push protection would block); the
    // linted `code` string still holds the full token, so the rule fires.
    @Test
    fun `flags a Stripe live secret key`() {
        val token = "sk_" + "live_" + "0123456789abcdefghijklmno"
        val code = """
            val key = "$token"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags a Stripe restricted live key`() {
        val token = "rk_" + "live_" + "abcdefghijklmnopqrstuvwxyz"
        val code = """
            val key = "$token"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a test-mode key`() {
        val code = """
            val key = "sk_test_0123456789abcdefghijklmno"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores a value loaded from the environment`() {
        val code = """
            val key = System.getenv("STRIPE_SECRET_KEY")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

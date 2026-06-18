package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusRestClientInsecureUrlRuleTest {

    private val rule = QuarkusRestClientInsecureUrlRule(Config.empty)

    @Test
    fun `flags RegisterRestClient with http baseUri`() {
        val code = """
            @RegisterRestClient(baseUri = "http://payment-service:8080")
            interface PaymentClient {
                fun charge(amount: Long): Response
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores RegisterRestClient with https baseUri`() {
        val code = """
            @RegisterRestClient(baseUri = "https://payment-service:8443")
            interface PaymentClient {
                fun charge(amount: Long): Response
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores RegisterRestClient with configKey (URI in properties)`() {
        val code = """
            @RegisterRestClient(configKey = "payment-service")
            interface PaymentClient {
                fun charge(amount: Long): Response
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores RegisterRestClient without url argument`() {
        val code = """
            @RegisterRestClient
            interface PaymentClient {
                fun charge(amount: Long): Response
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with missing auth code`() {
        val code = """
            @GET
            fun listProducts(): List<Product>
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

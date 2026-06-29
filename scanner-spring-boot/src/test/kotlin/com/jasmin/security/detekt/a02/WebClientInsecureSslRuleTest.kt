package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class WebClientInsecureSslRuleTest {

    private val rule = WebClientInsecureSslRule(Config.empty)

    @Test
    fun `flags trustManager with InsecureTrustManagerFactory`() {
        val code = """
            fun ssl() = SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores trustManager with a real CA`() {
        val code = """
            fun ssl() = SslContextBuilder.forClient()
                .trustManager(java.io.File("ca.pem"))
                .build()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

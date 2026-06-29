package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxEventBusBridgeOpenRuleTest {

    private val rule = VertxEventBusBridgeOpenRule(Config.empty)

    @Test
    fun `flags setAddressRegex matching everything`() {
        val code = """
            fun bridge() = SockJSBridgeOptions().addInboundPermitted(PermittedOptions().setAddressRegex(".*"))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setAddress wildcard`() {
        val code = """
            fun bridge() = PermittedOptions().setAddress("*")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a specific address regex`() {
        val code = """
            fun bridge() = PermittedOptions().setAddressRegex("news\\..+")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores a specific address`() {
        val code = """
            fun bridge() = PermittedOptions().setAddress("news.updates")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

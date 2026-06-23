package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class HardcodedJwtTokenRuleTest {

    private val rule = HardcodedJwtTokenRule(Config.empty)

    @Test
    fun `flags a hardcoded signed JWT literal`() {
        val code = """
            val token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysignature123"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a value loaded from the environment`() {
        val code = """
            val token = System.getenv("JWT")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores an unrelated string`() {
        val code = """
            val note = "the header starts with eyJ when base64 encoded"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

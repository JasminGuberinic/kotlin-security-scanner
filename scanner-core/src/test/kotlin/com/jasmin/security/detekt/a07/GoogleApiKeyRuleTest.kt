package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class GoogleApiKeyRuleTest {

    private val rule = GoogleApiKeyRule(Config.empty)

    @Test
    fun `flags a hardcoded Google API key`() {
        val code = """
            val key = "AIzaSyDuMmYkEy0123456789abcdefABCDEFghi"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a value loaded from the environment`() {
        val code = """
            val key = System.getenv("GOOGLE_API_KEY")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores an unrelated string`() {
        val code = """
            val note = "AIza is the Google key prefix but this is not a key"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

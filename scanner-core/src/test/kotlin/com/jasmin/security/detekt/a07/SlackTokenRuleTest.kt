package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SlackTokenRuleTest {

    private val rule = SlackTokenRule(Config.empty)

    // The dummy tokens are assembled at runtime so this source file never contains a
    // contiguous Slack-format literal (which GitHub push protection would block); the
    // linted `code` string still holds the full token, so the rule fires.
    @Test
    fun `flags a hardcoded Slack bot token`() {
        val token = "xox" + "b-1234567890-abcdefghijklmnop"
        val code = """
            val token = "$token"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags a hardcoded Slack user token`() {
        val token = "xox" + "p-9876543210-zyxwvutsrqponml"
        val code = """
            val token = "$token"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a value loaded from the environment`() {
        val code = """
            val token = System.getenv("SLACK_TOKEN")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores an unrelated string`() {
        val code = """
            val msg = "posting to slack channel"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxSessionCookieInsecureRuleTest {

    private val rule = VertxSessionCookieInsecureRule(Config.empty)

    @Test
    fun `flags setCookieSecureFlag false`() {
        val code = """
            fun session(store: Any) = SessionHandler.create(store).setCookieSecureFlag(false)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores setCookieSecureFlag true`() {
        val code = """
            fun session(store: Any) = SessionHandler.create(store).setCookieSecureFlag(true)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

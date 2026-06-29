package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxStaticHandlerDirectoryListingRuleTest {

    private val rule = VertxStaticHandlerDirectoryListingRule(Config.empty)

    @Test
    fun `flags setDirectoryListing true`() {
        val code = """
            fun static() = StaticHandler.create("webroot").setDirectoryListing(true)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores setDirectoryListing false`() {
        val code = """
            fun static() = StaticHandler.create("webroot").setDirectoryListing(false)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

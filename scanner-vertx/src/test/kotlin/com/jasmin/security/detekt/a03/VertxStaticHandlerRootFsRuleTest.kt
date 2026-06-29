package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxStaticHandlerRootFsRuleTest {

    private val rule = VertxStaticHandlerRootFsRule(Config.empty)

    @Test
    fun `flags StaticHandler serving filesystem root`() {
        val code = """
            fun static() = StaticHandler.create("/")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags setAllowRootFileSystemAccess true`() {
        val code = """
            fun static() = StaticHandler.create().setAllowRootFileSystemAccess(true)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a dedicated webroot`() {
        val code = """
            fun static() = StaticHandler.create("webroot")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

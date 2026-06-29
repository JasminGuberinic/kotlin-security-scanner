package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxJwtNoneAlgorithmRuleTest {

    private val rule = VertxJwtNoneAlgorithmRule(Config.empty)

    @Test
    fun `flags setAlgorithm none`() {
        val code = """
            fun jwt() = PubSecKeyOptions().setAlgorithm("none")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a real algorithm`() {
        val code = """
            fun jwt() = PubSecKeyOptions().setAlgorithm("RS256")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

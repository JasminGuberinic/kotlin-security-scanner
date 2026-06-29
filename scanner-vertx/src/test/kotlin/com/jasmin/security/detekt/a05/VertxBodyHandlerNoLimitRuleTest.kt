package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxBodyHandlerNoLimitRuleTest {

    private val rule = VertxBodyHandlerNoLimitRule(Config.empty)

    @Test
    fun `flags BodyHandler create without a limit`() {
        val code = """
            fun routes() = router.route().handler(BodyHandler.create())
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores BodyHandler create with a body limit`() {
        val code = """
            fun routes() = router.route().handler(BodyHandler.create().setBodyLimit(10485760))
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated create call`() {
        val code = """
            fun x() = SomeOther.create()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

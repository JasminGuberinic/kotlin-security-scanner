package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxCorsWildcardRuleTest {

    private val rule = VertxCorsWildcardRule(Config.empty)

    @Test
    fun `flags CorsHandler create with regex wildcard`() {
        val code = """
            fun cors() = router.route().handler(CorsHandler.create(".*"))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags addOrigin wildcard`() {
        val code = """
            fun cors() = CorsHandler.create().addOrigin("*")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a trusted origin`() {
        val code = """
            fun cors() = CorsHandler.create().addOrigin("https://app.example.com")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated create call`() {
        val code = """
            fun x() = SomeOther.create(".*")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

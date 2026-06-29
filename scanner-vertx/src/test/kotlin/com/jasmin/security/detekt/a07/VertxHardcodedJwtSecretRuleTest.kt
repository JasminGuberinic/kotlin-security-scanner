package com.jasmin.security.detekt.a07

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class VertxHardcodedJwtSecretRuleTest {

    private val rule = VertxHardcodedJwtSecretRule(Config.empty)

    @Test
    fun `flags PubSecKeyOptions setBuffer with a literal secret`() {
        val code = """
            fun jwt() = PubSecKeyOptions().setAlgorithm("HS256").setBuffer("my-hardcoded-jwt-secret")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores a secret loaded from the environment`() {
        val code = """
            fun jwt() = PubSecKeyOptions().setBuffer(System.getenv("JWT_SECRET"))
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores setBuffer on a non-JWT receiver`() {
        val code = """
            fun raw() = Buffer.buffer().setBuffer("payload")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

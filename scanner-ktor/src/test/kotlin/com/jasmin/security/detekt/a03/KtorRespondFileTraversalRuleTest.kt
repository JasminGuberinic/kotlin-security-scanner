package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorRespondFileTraversalRuleTest {

    private val rule = KtorRespondFileTraversalRule(Config.empty)

    @Test
    fun `flags respondFile path from request parameters`() {
        val code = """
            suspend fun handle(call: Any, baseDir: Any) {
                call.respondFile(baseDir, call.parameters["file"]!!)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores respondFile with a constant path`() {
        val code = """
            suspend fun handle(call: Any, baseDir: Any) {
                call.respondFile(baseDir, "logo.png")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

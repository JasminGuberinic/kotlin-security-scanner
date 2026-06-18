package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorSecurityHeadersMissingRuleTest {

    private val rule = KtorSecurityHeadersMissingRule(Config.empty)

    @Test
    fun `flags DefaultHeaders install without X-Frame-Options`() {
        val code = """
            fun configure() {
                install(DefaultHeaders) {
                    header("X-Content-Type-Options", "nosniff")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags DefaultHeaders install with empty lambda`() {
        val code = """
            fun configure() {
                install(DefaultHeaders) {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores DefaultHeaders with X-Frame-Options`() {
        val code = """
            install(DefaultHeaders) {
                header("X-Frame-Options", "DENY")
                header("X-Content-Type-Options", "nosniff")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with Sessions install`() {
        val code = """
            install(Sessions) {
                cookie<UserSession>("SESSION")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

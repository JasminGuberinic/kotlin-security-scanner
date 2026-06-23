package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorDevelopmentModeRuleTest {

    private val rule = KtorDevelopmentModeRule(Config.empty)

    @Test
    fun `flags developmentMode set to true`() {
        val code = """
            class Env { var developmentMode: Boolean = false }
            fun config(env: Env) {
                env.developmentMode = true
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores developmentMode set from the environment`() {
        val code = """
            class Env { var developmentMode: Boolean = false }
            fun config(env: Env) {
                env.developmentMode = System.getenv("KTOR_DEV") == "true"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores developmentMode set to false`() {
        val code = """
            class Env { var developmentMode: Boolean = false }
            fun config(env: Env) {
                env.developmentMode = false
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

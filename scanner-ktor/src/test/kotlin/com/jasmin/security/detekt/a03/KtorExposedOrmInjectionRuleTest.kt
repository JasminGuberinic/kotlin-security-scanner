package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorExposedOrmInjectionRuleTest {

    private val rule = KtorExposedOrmInjectionRule(Config.empty)

    @Test
    fun `flags exec with string interpolation`() {
        val code = """
            transaction {
                exec("SELECT * FROM users WHERE name = '${'$'}name'")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores exec with string literal`() {
        val code = """
            transaction {
                exec("SELECT count(*) FROM users WHERE active = true")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Exposed DSL query`() {
        val code = """
            transaction {
                Users.select { Users.name eq name }.toList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with XSS response code`() {
        val code = """
            get("/search") {
                call.respondText("<h1>Results</h1>", ContentType.Text.Html)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorSensitiveRouteParamRuleTest {

    private val rule = KtorSensitiveRouteParamRule(Config.empty)

    @Test
    fun `flags call_parameters used in exec`() {
        val code = """
            get("/user") {
                val id = call.parameters["id"]
                exec("SELECT * FROM users WHERE id = ${'$'}{call.parameters["id"]}")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores call_parameters used safely with DSL`() {
        val code = """
            get("/user/{id}") {
                val id = call.parameters["id"]?.toLongOrNull() ?: return@get
                val user = transaction { Users.select { Users.id eq id }.singleOrNull() }
                call.respond(user ?: HttpStatusCode.NotFound)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores exec with static literal`() {
        val code = """
            get("/stats") {
                val count = exec("SELECT count(*) FROM users WHERE active = true")
                call.respond(count)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

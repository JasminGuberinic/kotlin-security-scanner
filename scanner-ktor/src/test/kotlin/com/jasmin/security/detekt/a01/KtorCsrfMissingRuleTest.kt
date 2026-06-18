package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorCsrfMissingRuleTest {

    private val rule = KtorCsrfMissingRule(Config.empty)

    @Test
    fun `flags post route without CSRF check`() {
        val code = """
            routing {
                post("/transfer") {
                    val body = call.receive<TransferRequest>()
                    transferService.execute(body)
                    call.respond(HttpStatusCode.OK)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores post route with X-CSRF-Token header check`() {
        val code = """
            routing {
                post("/transfer") {
                    val csrf = call.request.header("X-CSRF-Token")
                    require(csrf != null)
                    val body = call.receive<TransferRequest>()
                    call.respond(HttpStatusCode.OK)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores get route (safe read-only)`() {
        val code = """
            routing {
                get("/accounts") {
                    call.respond(accountService.findAll())
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

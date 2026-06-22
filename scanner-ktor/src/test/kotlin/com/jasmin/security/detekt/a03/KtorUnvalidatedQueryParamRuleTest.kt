package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorUnvalidatedQueryParamRuleTest {

    private val rule = KtorUnvalidatedQueryParamRule(Config.empty)

    @Test
    fun `flags call parameters with force unwrap`() {
        val code = """
            get("/users/{id}") {
                val id = call.parameters["id"]!!
                call.respondText("User ${'$'}id")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags parameters subscript with force unwrap`() {
        val code = """
            get("/search") {
                val query = parameters["q"]!!
                val results = searchService.search(query)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores parameters with safe call and elvis`() {
        val code = """
            get("/users/{id}") {
                val id = call.parameters["id"] ?: return@get call.respond(HttpStatusCode.BadRequest)
                call.respondText("User ${'$'}id")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores parameters with toLongOrNull`() {
        val code = """
            get("/users/{id}") {
                val id = call.parameters["id"]?.toLongOrNull() ?: return@get call.respond(HttpStatusCode.BadRequest)
                call.respondText("User ${'$'}id")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with file upload traversal code`() {
        val code = """
            post("/upload") {
                val multipart = call.receiveMultipart()
                multipart.forEachPart { part ->
                    if (part is PartData.FileItem) {
                        val safeName = part.originalFileName!!.substringAfterLast("/")
                        val file = File(uploadDir, safeName)
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

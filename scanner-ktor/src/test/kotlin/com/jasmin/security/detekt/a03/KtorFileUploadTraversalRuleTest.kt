package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorFileUploadTraversalRuleTest {

    private val rule = KtorFileUploadTraversalRule(Config.empty)

    @Test
    fun `flags File with originalFileName`() {
        val code = """
            post("/upload") {
                val multipart = call.receiveMultipart()
                multipart.forEachPart { part ->
                    if (part is PartData.FileItem) {
                        val file = File(part.originalFileName!!)
                        file.writeBytes(part.streamProvider().readBytes())
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Path with originalFileName`() {
        val code = """
            post("/upload") {
                val multipart = call.receiveMultipart()
                multipart.forEachPart { part ->
                    if (part is PartData.FileItem) {
                        val path = Path(part.originalFileName!!)
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores File with sanitized filename`() {
        val code = """
            post("/upload") {
                val multipart = call.receiveMultipart()
                multipart.forEachPart { part ->
                    if (part is PartData.FileItem) {
                        val safeName = part.originalFileName!!.substringAfterLast("/").replace("..", "")
                        val file = File(uploadDir, safeName)
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores File with literal path`() {
        val code = """
            fun createTempFile() {
                val file = File("/tmp/safe-output.txt")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `flags Paths get with originalFileName`() {
        val code = """
            post("/upload") {
                val multipart = call.receiveMultipart()
                multipart.forEachPart { part ->
                    if (part is PartData.FileItem) {
                        val path = Paths.get(uploadDir, part.originalFileName!!)
                    }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores File with inline-sanitized originalFileName`() {
        val code = """
            post("/upload") {
                val file = File(uploadDir, part.originalFileName!!.replace("..", "").substringAfterLast("/"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Paths get with sanitized originalFileName via substringAfterLast`() {
        val code = """
            post("/upload") {
                val path = Paths.get(uploadDir, part.originalFileName!!.substringAfterLast("/"))
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with exposed ORM concat code`() {
        val code = """
            fun findUser(id: Long) {
                transaction {
                    exec("SELECT * FROM users WHERE id = " + id)
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

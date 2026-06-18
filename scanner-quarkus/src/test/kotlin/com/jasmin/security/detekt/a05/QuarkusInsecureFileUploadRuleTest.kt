package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusInsecureFileUploadRuleTest {

    private val rule = QuarkusInsecureFileUploadRule(Config.empty)

    @Test
    fun `flags FileUpload fileName() used in file path`() {
        val code = """
            @POST
            @Consumes(MediaType.MULTIPART_FORM_DATA)
            fun upload(file: FileUpload): Response {
                val dest = File(uploadDir, file.fileName())
                file.uploadedFile().copyTo(dest)
                return Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags FormData fileName in Paths_get`() {
        val code = """
            fun save(multipart: MultipartBody): Response {
                val path = Paths.get(base, multipart.fileName())
                return Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores upload method without fileName`() {
        val code = """
            fun upload(file: FileUpload): Response {
                val safeName = UUID.randomUUID().toString() + ".pdf"
                file.uploadedFile().copyTo(File(uploadDir, safeName))
                return Response.ok().build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-upload method`() {
        val code = """
            fun listFiles(): List<String> {
                return File(uploadDir).list()?.toList() ?: emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with QuarkusMultipart fixture`() {
        val code = """
            quarkus.http.limits.max-body-size=10M
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

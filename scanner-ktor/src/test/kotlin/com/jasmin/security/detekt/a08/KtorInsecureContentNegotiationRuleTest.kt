package com.jasmin.security.detekt.a08

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorInsecureContentNegotiationRuleTest {

    private val rule = KtorInsecureContentNegotiationRule(Config.empty)

    @Test
    fun `flags java serialized object content type`() {
        val code = """
            fun Application.configure() {
                install(ContentNegotiation) {
                    register(ContentType.parse("application/x-java-serialized-object"), JavaSerializationConverter())
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags java-serialized-object string`() {
        val code = """
            val javaSerialType = "application/x-java-serialized-object"
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores json content type`() {
        val code = """
            fun Application.configure() {
                install(ContentNegotiation) {
                    json()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores application json string`() {
        val code = """
            val jsonType = "application/json"
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with unsafe deserialization code`() {
        val code = """
            fun configure() {
                val mapper = ObjectMapper()
                mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a08

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JacksonUnsafeDeserializationRuleTest {

    private val rule = JacksonUnsafeDeserializationRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags enableDefaultTyping call`() {
        val code = """
            fun mapper(): ObjectMapper = ObjectMapper().apply { enableDefaultTyping() }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags activateDefaultTyping call`() {
        val code = """
            fun mapper(): ObjectMapper = ObjectMapper().also {
                it.activateDefaultTyping(LaissezFaireSubTypeValidator.instance)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags JsonTypeInfo annotation with Id CLASS`() {
        val code = """
            @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
            open class Animal(val name: String)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags JsonTypeInfo annotation with MINIMAL_CLASS`() {
        val code = """
            @JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS, include = As.PROPERTY, property = "@c")
            abstract class Vehicle
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags JsonTypeInfo with positional Id CLASS argument`() {
        val code = """
            @JsonTypeInfo(JsonTypeInfo.Id.CLASS, include = As.PROPERTY, property = "@c")
            open class Animal(val name: String)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores JsonTypeInfo with positional Id NAME argument`() {
        val code = """
            @JsonTypeInfo(JsonTypeInfo.Id.NAME, include = As.PROPERTY, property = "type")
            open class Shape
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }


    @Test
    fun `ignores ObjectMapper without enableDefaultTyping`() {
        val code = """
            fun mapper(): ObjectMapper = ObjectMapper()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores JsonTypeInfo with Id NAME`() {
        val code = """
            @JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = As.PROPERTY, property = "type")
            open class Shape
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on InsecureDeserialization fixture`() {
        val code = """
            fun deserialize(input: InputStream): Any =
                ObjectInputStream(input).readObject()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a08

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecureDeserializationRuleTest {

    private val rule = InsecureDeserializationRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags ObjectInputStream construction`() {
        val code = """
            fun deserialize(bytes: ByteArray): Any {
                val ois = ObjectInputStream(bytes.inputStream())
                return ois.readObject()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags ObjectInputStream in try block`() {
        val code = """
            fun load(stream: InputStream): Any? = try {
                ObjectInputStream(stream).readObject()
            } catch (e: Exception) { null }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags XMLDecoder construction`() {
        val code = """
            fun decode(input: InputStream): Any {
                val decoder = XMLDecoder(input)
                return decoder.readObject()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores ObjectMapper JSON deserialization`() {
        val code = """
            import com.fasterxml.jackson.databind.ObjectMapper
            fun deserialize(json: String): User {
                return ObjectMapper().readValue(json, User::class.java)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores BufferedInputStream`() {
        val code = """
            fun read(stream: InputStream): ByteArray {
                return BufferedInputStream(stream).readBytes()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on XXE factory fixture`() {
        val code = """
            import javax.xml.parsers.DocumentBuilderFactory
            fun parse() {
                val dbf = DocumentBuilderFactory.newInstance()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

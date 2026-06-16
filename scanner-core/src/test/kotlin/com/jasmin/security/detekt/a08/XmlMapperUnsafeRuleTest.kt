package com.jasmin.security.detekt.a08

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class XmlMapperUnsafeRuleTest {

    private val rule = XmlMapperUnsafeRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags bare XmlMapper constructor`() {
        val code = """
            fun mapper(): XmlMapper = XmlMapper()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags XmlMapper in apply block`() {
        val code = """
            fun mapper() = XmlMapper().apply {
                registerModule(KotlinModule.Builder().build())
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags XmlMapper stored in val`() {
        val code = """
            val xmlMapper = XmlMapper()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores ObjectMapper`() {
        val code = """
            val mapper = ObjectMapper()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated constructors`() {
        val code = """
            val sb = StringBuilder()
            val list = ArrayList<String>()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on JacksonUnsafeDeserialization fixture`() {
        val code = """
            fun mapper() = ObjectMapper().apply { enableDefaultTyping() }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

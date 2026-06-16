package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class XxeInjectionRuleTest {

    private val rule = XxeInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags DocumentBuilderFactory newInstance`() {
        val code = """
            import javax.xml.parsers.DocumentBuilderFactory
            fun parse(xml: String) {
                val dbf = DocumentBuilderFactory.newInstance()
                dbf.newDocumentBuilder().parse(xml)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags SAXParserFactory newInstance`() {
        val code = """
            import javax.xml.parsers.SAXParserFactory
            fun parse(xml: String) {
                val spf = SAXParserFactory.newInstance()
                spf.newSAXParser()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags XMLInputFactory newInstance`() {
        val code = """
            import javax.xml.stream.XMLInputFactory
            fun parse(stream: InputStream) {
                val xif = XMLInputFactory.newInstance()
                xif.createXMLStreamReader(stream)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags TransformerFactory newInstance`() {
        val code = """
            import javax.xml.transform.TransformerFactory
            fun transform() {
                val tf = TransformerFactory.newInstance()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores newInstance not on XML factory`() {
        val code = """
            fun create() {
                val cal = Calendar.newInstance()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores other factory newInstance calls`() {
        val code = """
            fun create() {
                val format = DateFormat.newInstance()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on ObjectInputStream deserialization fixture`() {
        val code = """
            fun deserialize(input: InputStream) {
                val ois = ObjectInputStream(input)
                ois.readObject()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

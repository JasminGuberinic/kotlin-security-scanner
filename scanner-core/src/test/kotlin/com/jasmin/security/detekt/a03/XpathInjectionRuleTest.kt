package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class XpathInjectionRuleTest {

    private val rule = XpathInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags evaluate with interpolated expression`() {
        val code = """
            fun findUser(name: String): Any? =
                xpath.evaluate("//user[@name='${'$'}name']", doc, XPathConstants.NODE)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags selectNodes with interpolated expression`() {
        val code = """
            fun getNodes(id: String) =
                doc.selectNodes("//item[@id='${'$'}id']")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags selectSingleNode with interpolated expression`() {
        val code = """
            fun getNode(role: String) =
                root.selectSingleNode("//user[@role='${'$'}role']")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags evaluate with concatenated expression`() {
        val code = """
            fun findUser(name: String): Any? =
                xpath.evaluate("//user[@name='" + name + "']", doc, XPathConstants.NODE)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores evaluate with constant concatenated expression`() {
        val code = """
            fun getAdmins(): Any? =
                xpath.evaluate("//user[@role='" + "admin" + "']", doc, XPathConstants.NODESET)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores evaluate with literal expression`() {
        val code = """
            fun getAllAdmins(): Any? =
                xpath.evaluate("//user[@role='admin']", doc, XPathConstants.NODESET)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores evaluate with variable (not string template)`() {
        val code = """
            fun findByExpr(expr: String): Any? =
                xpath.evaluate(expr, doc, XPathConstants.NODE)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores selectNodes with literal`() {
        val code = """
            fun getItems() = doc.selectNodes("//items/item")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on LDAP injection fixture`() {
        val code = """
            fun findUser(username: String) {
                ctx.search("ou=users,dc=example,dc=com", "(uid=${'$'}username)", controls)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class JndiInjectionRuleTest {

    private val rule = JndiInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags lookup with variable argument`() {
        val code = """
            fun resolve(name: String): Any = ctx.lookup(name)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags lookup with interpolated string`() {
        val code = """
            fun resolve(host: String): Any = ctx.lookup("ldap://${'$'}host/exploit")
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags rebind with variable argument`() {
        val code = """
            fun register(name: String, obj: Any) {
                ctx.rebind(name, obj)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags lookup with method call result`() {
        val code = """
            fun resolve(req: HttpServletRequest): Any =
                ctx.lookup(req.getParameter("resource"))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores lookup with literal JNDI name`() {
        val code = """
            fun getDataSource(): Any = ctx.lookup("java:comp/env/jdbc/MyDs")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores lookup with literal env name`() {
        val code = """
            fun getBean(): Any = ctx.lookup("java:module/MyBean")
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on XPath injection fixture`() {
        val code = """
            fun findUser(name: String): Any? =
                xpath.evaluate("//user[@name='${'$'}name']", doc, XPathConstants.NODE)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

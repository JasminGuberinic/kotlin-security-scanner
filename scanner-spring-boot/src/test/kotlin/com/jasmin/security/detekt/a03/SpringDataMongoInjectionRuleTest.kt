package com.jasmin.security.detekt.a03

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringDataMongoInjectionRuleTest {

    private val rule = SpringDataMongoInjectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags Criteria where with variable field`() {
        val code = """
            fun findBy(field: String, value: String) =
                mongoTemplate.find(Query(Criteria.where(field).is(value)), User::class.java)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Criteria where with interpolated field`() {
        val code = """
            fun findBy(prefix: String) =
                mongoTemplate.find(Query(Criteria.where("${'$'}prefix.name").is("test")), Doc::class.java)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Criteria where with method call result`() {
        val code = """
            fun findBy(req: HttpServletRequest) =
                mongoTemplate.find(
                    Query(Criteria.where(req.getParameter("field")).is("value")),
                    Document::class.java,
                )
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores Criteria where with literal field`() {
        val code = """
            fun findByUsername(username: String) =
                mongoTemplate.find(Query(Criteria.where("username").is(username)), User::class.java)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores where call on non-Criteria receiver`() {
        val code = """
            fun filter(items: List<String>, pred: (String) -> Boolean) = items.filter { pred(it) }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on SpelInjection fixture`() {
        val code = """
            fun evaluate(expr: String) = SpelExpressionParser().parseExpression(expr).getValue()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

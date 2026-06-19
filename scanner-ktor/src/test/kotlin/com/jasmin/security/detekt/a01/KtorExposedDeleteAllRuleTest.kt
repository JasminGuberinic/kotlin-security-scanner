package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KtorExposedDeleteAllRuleTest {

    private val rule = KtorExposedDeleteAllRule(Config.empty)

    @Test
    fun `flags deleteAll call`() {
        val code = """
            fun purgeUsers() {
                transaction {
                    Users.deleteAll()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores deleteWhere with condition`() {
        val code = """
            fun removeInactiveUsers() {
                transaction {
                    Users.deleteWhere { Users.active eq false }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores delete DSL with where block`() {
        val code = """
            fun removeById(userId: Long) {
                transaction {
                    Users.deleteWhere { Users.id eq userId }
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with Exposed ORM injection code`() {
        val code = """
            fun searchUser(name: String) {
                transaction {
                    exec("SELECT * FROM users WHERE name = '${'$'}name'")
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

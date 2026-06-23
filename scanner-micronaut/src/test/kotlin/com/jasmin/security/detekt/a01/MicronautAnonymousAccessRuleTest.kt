package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautAnonymousAccessRuleTest {

    private val rule = MicronautAnonymousAccessRule(Config.empty)

    @Test
    fun `flags anonymous access on a Delete endpoint`() {
        val code = """
            import io.micronaut.http.annotation.Delete
            import io.micronaut.security.annotation.Secured
            import io.micronaut.security.rules.SecurityRule

            class AdminController {
                @Delete("/users/{id}")
                @Secured(SecurityRule.IS_ANONYMOUS)
                fun delete(id: Long) {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags anonymous string expression on a Post endpoint`() {
        val code = """
            import io.micronaut.http.annotation.Post
            import io.micronaut.security.annotation.Secured

            class OrderController {
                @Post("/orders")
                @Secured("isAnonymous()")
                fun create() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores authenticated write endpoint`() {
        val code = """
            import io.micronaut.http.annotation.Post
            import io.micronaut.security.annotation.Secured
            import io.micronaut.security.rules.SecurityRule

            class OrderController {
                @Post("/orders")
                @Secured(SecurityRule.IS_AUTHENTICATED)
                fun create() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores anonymous access on a read endpoint`() {
        val code = """
            import io.micronaut.http.annotation.Get
            import io.micronaut.security.annotation.Secured
            import io.micronaut.security.rules.SecurityRule

            class PublicController {
                @Get("/health")
                @Secured(SecurityRule.IS_ANONYMOUS)
                fun health() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ReactiveSecurityContextHolderRuleTest {

    private val rule = ReactiveSecurityContextHolderRule(Config.empty)

    @Test
    fun `flags SecurityContextHolder in a Mono-returning function`() {
        val code = """
            import reactor.core.publisher.Mono
            import org.springframework.security.core.context.SecurityContextHolder
            fun me(): Mono<String> {
                val auth = SecurityContextHolder.getContext().authentication
                return Mono.just(auth.name)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores SecurityContextHolder in a non-reactive (MVC) function`() {
        val code = """
            import org.springframework.security.core.context.SecurityContextHolder
            fun me(): String {
                return SecurityContextHolder.getContext().authentication.name
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores ReactiveSecurityContextHolder`() {
        val code = """
            import reactor.core.publisher.Mono
            fun me(): Mono<String> {
                return ReactiveSecurityContextHolder.getContext().map { it.authentication.name }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

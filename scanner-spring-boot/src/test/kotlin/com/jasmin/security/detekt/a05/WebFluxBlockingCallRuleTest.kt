package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class WebFluxBlockingCallRuleTest {

    private val rule = WebFluxBlockingCallRule(Config.empty)

    @Test
    fun `flags block inside a Mono-returning function`() {
        val code = """
            import reactor.core.publisher.Mono
            fun handler(): Mono<String> {
                val user = userRepo.findById(id).block()
                return Mono.just(user)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores block in a non-reactive function`() {
        val code = """
            fun loadAtStartup(): String {
                return configRepo.find().block()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores reactive composition without blocking`() {
        val code = """
            import reactor.core.publisher.Mono
            fun handler(): Mono<String> {
                return userRepo.findById(id).map { it.name }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

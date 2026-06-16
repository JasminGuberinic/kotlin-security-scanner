package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DisabledHttpSecurityRuleTest {

    private val rule = DisabledHttpSecurityRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags anyRequest-permitAll in authorizeHttpRequests`() {
        val code = """
            import org.springframework.security.config.annotation.web.builders.HttpSecurity
            @Bean
            fun filterChain(http: HttpSecurity): SecurityFilterChain {
                http.authorizeHttpRequests { auth ->
                    auth.anyRequest().permitAll()
                }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags anyRequest-permitAll in authorizeRequests`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.authorizeRequests { auth ->
                    auth.anyRequest().permitAll()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags anyRequest-permitAll with different receiver name`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.authorizeHttpRequests { requests ->
                    requests.anyRequest().permitAll()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores anyRequest-authenticated — secure default`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.authorizeHttpRequests { auth ->
                    auth.anyRequest().authenticated()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores specific path with permitAll`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.authorizeHttpRequests { auth ->
                    auth.requestMatchers("/public/**").permitAll()
                    auth.anyRequest().authenticated()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores anyRequest-denyAll`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.authorizeHttpRequests { auth ->
                    auth.anyRequest().denyAll()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on MissingAuthorization fixture`() {
        val code = """
            import org.springframework.web.bind.annotation.GetMapping
            class UserController {
                @GetMapping("/users")
                fun list(): List<String> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

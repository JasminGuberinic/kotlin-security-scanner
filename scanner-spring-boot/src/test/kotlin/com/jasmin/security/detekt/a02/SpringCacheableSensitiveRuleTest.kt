package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SpringCacheableSensitiveRuleTest {

    private val rule = SpringCacheableSensitiveRule(Config.empty)

    @Test
    fun `flags Cacheable on method with password in name`() {
        val code = """
            @Cacheable("passwords")
            fun getUserPassword(userId: Long): String = passwordStore.get(userId)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Cacheable on method with token in name`() {
        val code = """
            @Cacheable("tokens")
            fun getAccessToken(userId: Long): String = tokenService.generate(userId)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Cacheable on method with secret in name`() {
        val code = """
            @Cacheable("secrets")
            fun getApiSecret(clientId: String): String = secretStore.lookup(clientId)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Cacheable on non-sensitive method`() {
        val code = """
            @Cacheable("users")
            fun getUser(id: Long): UserDto = userRepository.findById(id)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores sensitive method name without Cacheable`() {
        val code = """
            fun getAccessToken(userId: Long): String = tokenService.generate(userId)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `does not interfere with weak bcrypt code`() {
        val code = """
            val encoder = BCryptPasswordEncoder(4)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

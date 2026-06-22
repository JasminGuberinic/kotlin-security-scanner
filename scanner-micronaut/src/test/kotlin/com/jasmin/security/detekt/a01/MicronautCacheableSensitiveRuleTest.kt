package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautCacheableSensitiveRuleTest {

    private val rule = MicronautCacheableSensitiveRule(Config.empty)

    @Test
    fun `flags Cacheable plus Secured on same method`() {
        val code = """
            import io.micronaut.cache.annotation.Cacheable
            import io.micronaut.security.annotation.Secured
            class UserService {
                @Cacheable("user-data")
                @Secured("IS_AUTHENTICATED")
                fun getUserProfile(id: Long): String = ""
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Cacheable method in Secured class`() {
        val code = """
            import io.micronaut.cache.annotation.Cacheable
            import io.micronaut.security.annotation.Secured
            @Secured("IS_AUTHENTICATED")
            class AccountService {
                @Cacheable("accounts")
                fun getAccount(id: Long): String = ""
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Cacheable on public method in unsecured class`() {
        val code = """
            import io.micronaut.cache.annotation.Cacheable
            class CatalogService {
                @Cacheable("products")
                fun listProducts(): List<String> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Secured method without Cacheable`() {
        val code = """
            import io.micronaut.security.annotation.Secured
            class UserService {
                @Secured("IS_AUTHENTICATED")
                fun updateProfile(id: Long): String = ""
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

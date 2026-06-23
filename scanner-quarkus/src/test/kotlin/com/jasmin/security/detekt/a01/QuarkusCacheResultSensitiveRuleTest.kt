package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusCacheResultSensitiveRuleTest {

    private val rule = QuarkusCacheResultSensitiveRule(Config.empty)

    @Test
    fun `flags CacheResult on a RolesAllowed method`() {
        val code = """
            import io.quarkus.cache.CacheResult
            import jakarta.annotation.security.RolesAllowed

            class ProfileService {
                @CacheResult(cacheName = "profile")
                @RolesAllowed("user")
                fun profile(id: Long): String = "p"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags CacheResult on an Authenticated method`() {
        val code = """
            import io.quarkus.cache.CacheResult
            import io.quarkus.security.Authenticated

            class ProfileService {
                @CacheResult(cacheName = "me")
                @Authenticated
                fun me(): String = "me"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores CacheResult on an unsecured method`() {
        val code = """
            import io.quarkus.cache.CacheResult

            class CatalogService {
                @CacheResult(cacheName = "catalog")
                fun catalog(): String = "c"
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

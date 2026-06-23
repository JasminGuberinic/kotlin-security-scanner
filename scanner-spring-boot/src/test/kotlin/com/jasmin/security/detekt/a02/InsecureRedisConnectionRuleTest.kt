package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class InsecureRedisConnectionRuleTest {

    private val rule = InsecureRedisConnectionRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags RedisStandaloneConfiguration constructor`() {
        val code = """
            @Bean
            fun redisConfig(): RedisConnectionFactory {
                val config = RedisStandaloneConfiguration("redis.internal", 6379)
                return LettuceConnectionFactory(config)
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(2)
    }

    @Test
    fun `flags bare LettuceConnectionFactory`() {
        val code = """
            val factory = LettuceConnectionFactory()
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags JedisConnectionFactory`() {
        val code = """
            val factory = JedisConnectionFactory(RedisStandaloneConfiguration("host", 6379))
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(2)
    }

    @Test
    fun `flags RedisStandaloneConfiguration without SSL`() {
        val code = """
            val config = RedisStandaloneConfiguration("redis.internal", 6379)
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores Redis configuration when SSL is enabled in the same declaration`() {
        val code = """
            val config = RedisStandaloneConfiguration("redis.internal", 6380).also { it.useSsl() }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores unrelated constructors`() {
        val code = """
            val client = RestTemplate()
            val props = Properties()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on InsecurePasswordEncoder fixture`() {
        val code = """
            fun encoder(): PasswordEncoder = NoOpPasswordEncoder.getInstance()
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

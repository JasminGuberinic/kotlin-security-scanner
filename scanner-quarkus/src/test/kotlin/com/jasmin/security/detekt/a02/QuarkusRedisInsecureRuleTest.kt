package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusRedisInsecureRuleTest {

    private val rule = QuarkusRedisInsecureRule(Config.empty)

    @Test
    fun `flags redis with cleartext scheme`() {
        val props = Properties().also {
            it["quarkus.redis.hosts"] = "redis://redis-server:6379"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `flags named redis client with cleartext scheme`() {
        val props = Properties().also {
            it["quarkus.redis.my-client.hosts"] = "redis://redis:6379"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores redis with TLS scheme`() {
        val props = Properties().also {
            it["quarkus.redis.hosts"] = "rediss://redis-server:6380"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated quarkus properties`() {
        val props = Properties().also {
            it["quarkus.datasource.db-kind"] = "postgresql"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusMongoInsecureRuleTest {

    private val rule = QuarkusMongoInsecureRule(Config.empty)

    @Test
    fun `flags mongodb connection without TLS`() {
        val props = Properties().also {
            it["quarkus.mongodb.connection-string"] = "mongodb://user:pass@mongo:27017/mydb"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores mongodb+srv connection`() {
        val props = Properties().also {
            it["quarkus.mongodb.connection-string"] = "mongodb+srv://user:pass@cluster.mongodb.net/mydb"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores mongodb connection with tls=true`() {
        val props = Properties().also {
            it["quarkus.mongodb.connection-string"] = "mongodb://mongo:27017/mydb?tls=true"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated quarkus properties`() {
        val props = Properties().also {
            it["quarkus.datasource.username"] = "admin"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

package com.jasmin.security.detekt.a02

import io.gitlab.arturbosch.detekt.api.Config
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Properties

class QuarkusGrpcInsecureRuleTest {

    private val rule = QuarkusGrpcInsecureRule(Config.empty)

    @Test
    fun `flags gRPC client with plain-text enabled`() {
        val props = Properties().also {
            it["quarkus.grpc.clients.my-service.plain-text"] = "true"
        }
        assertThat(rule.scanProperties(props)).hasSize(1)
    }

    @Test
    fun `ignores gRPC client without plain-text`() {
        val props = Properties().also {
            it["quarkus.grpc.clients.my-service.host"] = "grpc-server"
            it["quarkus.grpc.clients.my-service.ssl.trust-certificate"] = "ca.pem"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores gRPC client with plain-text false`() {
        val props = Properties().also {
            it["quarkus.grpc.clients.my-service.plain-text"] = "false"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }

    @Test
    fun `ignores unrelated quarkus grpc properties`() {
        val props = Properties().also {
            it["quarkus.grpc.server.port"] = "9000"
        }
        assertThat(rule.scanProperties(props)).isEmpty()
    }
}

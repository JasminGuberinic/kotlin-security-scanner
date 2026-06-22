package com.jasmin.security.detekt.a05

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautManagementEndpointInsecureRuleTest {

    private val rule = MicronautManagementEndpointInsecureRule(Config.empty)

    @Test
    fun `flags Endpoint class with Read method and no Secured`() {
        val code = """
            import io.micronaut.management.endpoint.annotation.Endpoint
            import io.micronaut.management.endpoint.annotation.Read
            @Endpoint("metrics")
            class MetricsEndpoint {
                @Read
                fun getMetrics(): Map<String, Any> = emptyMap()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `flags Endpoint class with Write method and no Secured`() {
        val code = """
            import io.micronaut.management.endpoint.annotation.Endpoint
            import io.micronaut.management.endpoint.annotation.Write
            @Endpoint("config")
            class ConfigEndpoint {
                @Write
                fun reload() {}
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Endpoint with class-level Secured`() {
        val code = """
            import io.micronaut.management.endpoint.annotation.Endpoint
            import io.micronaut.management.endpoint.annotation.Read
            import io.micronaut.security.annotation.Secured
            @Endpoint("health")
            @Secured("IS_AUTHENTICATED")
            class HealthEndpoint {
                @Read
                fun health(): Map<String, Any> = emptyMap()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Endpoint Read method with own Secured`() {
        val code = """
            import io.micronaut.management.endpoint.annotation.Endpoint
            import io.micronaut.management.endpoint.annotation.Read
            import io.micronaut.security.annotation.Secured
            @Endpoint("info")
            class InfoEndpoint {
                @Read
                @Secured("IS_AUTHENTICATED")
                fun info(): Map<String, Any> = emptyMap()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores non-Endpoint classes`() {
        val code = """
            import io.micronaut.http.annotation.Controller
            import io.micronaut.http.annotation.Get
            @Controller("/api")
            class ApiController {
                @Get
                fun list(): List<String> = emptyList()
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

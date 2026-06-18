package com.jasmin.security.detekt.a01

import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class QuarkusReactiveRouteNoAuthRuleTest {

    private val rule = QuarkusReactiveRouteNoAuthRule(Config.empty)

    @Test
    fun `flags Route method without auth annotation`() {
        val code = """
            @Route(path = "/profile", methods = [Route.HttpMethod.GET])
            fun getProfile(rc: RoutingContext) {
                rc.response().end("profile data")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).hasSize(1)
    }

    @Test
    fun `ignores Route with Authenticated`() {
        val code = """
            @Route(path = "/profile")
            @Authenticated
            fun getProfile(rc: RoutingContext) {
                rc.response().end("profile data")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Route with RolesAllowed`() {
        val code = """
            @Route(path = "/admin")
            @RolesAllowed("admin")
            fun adminPanel(rc: RoutingContext) {
                rc.response().end("admin")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores Route with PermitAll`() {
        val code = """
            @Route(path = "/health")
            @PermitAll
            fun health(rc: RoutingContext) {
                rc.response().end("ok")
            }
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }

    @Test
    fun `ignores regular function without Route`() {
        val code = """
            fun processOrder(orderId: Long): Order = orderService.findById(orderId)
        """.trimIndent()
        assertThat(rule.lint(code)).isEmpty()
    }
}

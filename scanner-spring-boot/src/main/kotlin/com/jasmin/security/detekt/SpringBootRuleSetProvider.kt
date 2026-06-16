package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.MissingAuthorizationRule
import com.jasmin.security.detekt.a05.PermissiveCorsRule
import com.jasmin.security.detekt.a05.SpringCsrfDisabledRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Spring Boot specific security rules.
 * Catches Spring Security misconfigurations and missing access control
 * on Spring MVC / Spring WebFlux endpoints.
 */
class SpringBootRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-spring-boot"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            MissingAuthorizationRule(config.subConfig("MissingAuthorization")),
            // A05 Security Misconfiguration
            SpringCsrfDisabledRule(config.subConfig("SpringCsrfDisabled")),
            PermissiveCorsRule(config.subConfig("PermissiveCors")),
        )
    )
}

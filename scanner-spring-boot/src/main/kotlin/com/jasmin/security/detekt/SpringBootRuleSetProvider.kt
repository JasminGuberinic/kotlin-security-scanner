package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.CoroutineSecurityContextLossRule
import com.jasmin.security.detekt.a01.CsrfTokenLeakRule
import com.jasmin.security.detekt.a01.DisabledHttpSecurityRule
import com.jasmin.security.detekt.a01.MissingAuthorizationRule
import com.jasmin.security.detekt.a01.OpenRedirectRule
import com.jasmin.security.detekt.a02.InsecurePasswordEncoderRule
import com.jasmin.security.detekt.a02.InsecureRedisConnectionRule
import com.jasmin.security.detekt.a02.InsecureSmtpConfigRule
import com.jasmin.security.detekt.a02.JwtExpirationMissingRule
import com.jasmin.security.detekt.a02.MissingHttpsRedirectRule
import com.jasmin.security.detekt.a02.WeakBcryptRoundsRule
import com.jasmin.security.detekt.a03.ELInjectionRule
import com.jasmin.security.detekt.a03.ResponseSplittingRule
import com.jasmin.security.detekt.a03.SpelInjectionRule
import com.jasmin.security.detekt.a03.SpringDataMongoInjectionRule
import com.jasmin.security.detekt.a03.ThymeleafSSTIRule
import com.jasmin.security.detekt.a04.MassAssignmentRule
import com.jasmin.security.detekt.a05.ExceptionDetailsExposedRule
import com.jasmin.security.detekt.a05.HttpMethodOverrideRule
import com.jasmin.security.detekt.a05.InsecureActuatorExposureRule
import com.jasmin.security.detekt.a05.PermissiveCorsRule
import com.jasmin.security.detekt.a05.SecurityHeadersMissingRule
import com.jasmin.security.detekt.a05.SpringCsrfDisabledRule
import com.jasmin.security.detekt.a10.WebClientSSRFRule
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
            OpenRedirectRule(config.subConfig("OpenRedirect")),
            DisabledHttpSecurityRule(config.subConfig("DisabledHttpSecurity")),
            CsrfTokenLeakRule(config.subConfig("CsrfTokenLeak")),
            CoroutineSecurityContextLossRule(config.subConfig("CoroutineSecurityContextLoss")),
            // A02 Cryptographic Failures
            InsecurePasswordEncoderRule(config.subConfig("InsecurePasswordEncoder")),
            WeakBcryptRoundsRule(config.subConfig("WeakBcryptRounds")),
            JwtExpirationMissingRule(config.subConfig("JwtExpirationMissing")),
            MissingHttpsRedirectRule(config.subConfig("MissingHttpsRedirect")),
            InsecureRedisConnectionRule(config.subConfig("InsecureRedisConnection")),
            InsecureSmtpConfigRule(config.subConfig("InsecureSmtpConfig")),
            // A03 Injection
            SpelInjectionRule(config.subConfig("SpelInjection")),
            ResponseSplittingRule(config.subConfig("ResponseSplitting")),
            ELInjectionRule(config.subConfig("ELInjection")),
            SpringDataMongoInjectionRule(config.subConfig("SpringDataMongoInjection")),
            ThymeleafSSTIRule(config.subConfig("ThymeleafSSTI")),
            // A04 Insecure Design
            MassAssignmentRule(config.subConfig("MassAssignment")),
            // A05 Security Misconfiguration
            SpringCsrfDisabledRule(config.subConfig("SpringCsrfDisabled")),
            PermissiveCorsRule(config.subConfig("PermissiveCors")),
            InsecureActuatorExposureRule(config.subConfig("InsecureActuatorExposure")),
            SecurityHeadersMissingRule(config.subConfig("SecurityHeadersMissing")),
            ExceptionDetailsExposedRule(config.subConfig("ExceptionDetailsExposed")),
            HttpMethodOverrideRule(config.subConfig("HttpMethodOverride")),
            // A10 Server-Side Request Forgery
            WebClientSSRFRule(config.subConfig("WebClientSSRF")),
        )
    )
}

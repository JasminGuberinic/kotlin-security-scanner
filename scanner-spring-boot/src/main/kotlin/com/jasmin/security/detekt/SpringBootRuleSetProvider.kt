package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.AsyncSecurityContextLossRule
import com.jasmin.security.detekt.a01.CoroutineSecurityContextLossRule
import com.jasmin.security.detekt.a01.CsrfTokenLeakRule
import com.jasmin.security.detekt.a01.DisabledHttpSecurityRule
import com.jasmin.security.detekt.a01.FeignClientInsecureUrlRule
import com.jasmin.security.detekt.a01.MissingAuthorizationRule
import com.jasmin.security.detekt.a01.OpenRedirectRule
import com.jasmin.security.detekt.a01.PermitAllAdminPathRule
import com.jasmin.security.detekt.a01.UnvalidatedForwardRule
import com.jasmin.security.detekt.a02.InsecurePasswordEncoderRule
import com.jasmin.security.detekt.a02.InsecureRedisConnectionRule
import com.jasmin.security.detekt.a02.InsecureSmtpConfigRule
import com.jasmin.security.detekt.a02.JwtExpirationMissingRule
import com.jasmin.security.detekt.a02.JwtSecretInPropertiesRule
import com.jasmin.security.detekt.a02.MissingHttpsRedirectRule
import com.jasmin.security.detekt.a02.OAuth2ClientSecretInPropertiesRule
import com.jasmin.security.detekt.a02.SpringCacheableSensitiveRule
import com.jasmin.security.detekt.a02.WeakBcryptRoundsRule
import com.jasmin.security.detekt.a03.ELInjectionRule
import com.jasmin.security.detekt.a03.EntityManagerJpqlInjectionRule
import com.jasmin.security.detekt.a03.ResponseSplittingRule
import com.jasmin.security.detekt.a03.SpelInjectionRule
import com.jasmin.security.detekt.a03.SpringDataMongoInjectionRule
import com.jasmin.security.detekt.a03.SpringDataSortInjectionRule
import com.jasmin.security.detekt.a03.ThymeleafSSTIRule
import com.jasmin.security.detekt.a04.MassAssignmentRule
import com.jasmin.security.detekt.a05.CloudConfigInsecureUriRule
import com.jasmin.security.detekt.a05.CrossOriginCredentialsWildcardRule
import com.jasmin.security.detekt.a05.ExceptionDetailsExposedRule
import com.jasmin.security.detekt.a05.H2ConsoleEnabledRule
import com.jasmin.security.detekt.a05.HttpMethodOverrideRule
import com.jasmin.security.detekt.a05.InsecureActuatorExposureRule
import com.jasmin.security.detekt.a05.KafkaInsecureProtocolRule
import com.jasmin.security.detekt.a05.KafkaTrustedPackagesWildcardRule
import com.jasmin.security.detekt.a05.PermissiveCorsRule
import com.jasmin.security.detekt.a05.SecurityHeadersMissingRule
import com.jasmin.security.detekt.a05.SpringActuatorShutdownEnabledRule
import com.jasmin.security.detekt.a05.SpringBootCookieNotHttpOnlyRule
import com.jasmin.security.detekt.a05.SpringBootInsecureFileUploadRule
import com.jasmin.security.detekt.a05.SpringCsrfDisabledRule
import com.jasmin.security.detekt.a05.SpringSecurityDebugEnabledRule
import com.jasmin.security.detekt.a07.HardcodedDatasourcePasswordRule
import com.jasmin.security.detekt.a07.InsecureRememberMeRule
import com.jasmin.security.detekt.a07.SpringBootHardcodedValueDefaultRule
import com.jasmin.security.detekt.a07.SpringBootNoOpPasswordEncoderRule
import com.jasmin.security.detekt.a08.SpringBootRequestBodyAnyTypeRule
import com.jasmin.security.detekt.a09.SecurityLoggingVerboseRule
import com.jasmin.security.detekt.a09.ShowSqlEnabledRule
import com.jasmin.security.detekt.a09.SpringBootExceptionBodyLeakRule
import com.jasmin.security.detekt.a10.RestTemplateSsrfRule
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
            MissingAuthorizationRule(config),
            OpenRedirectRule(config),
            DisabledHttpSecurityRule(config),
            CsrfTokenLeakRule(config),
            CoroutineSecurityContextLossRule(config),
            AsyncSecurityContextLossRule(config),
            FeignClientInsecureUrlRule(config),
            UnvalidatedForwardRule(config),
            PermitAllAdminPathRule(config),
            // A02 Cryptographic Failures
            InsecurePasswordEncoderRule(config),
            WeakBcryptRoundsRule(config),
            JwtExpirationMissingRule(config),
            JwtSecretInPropertiesRule(config),
            OAuth2ClientSecretInPropertiesRule(config),
            SpringCacheableSensitiveRule(config),
            MissingHttpsRedirectRule(config),
            InsecureRedisConnectionRule(config),
            InsecureSmtpConfigRule(config),
            // A03 Injection
            SpelInjectionRule(config),
            ResponseSplittingRule(config),
            ELInjectionRule(config),
            SpringDataMongoInjectionRule(config),
            ThymeleafSSTIRule(config),
            EntityManagerJpqlInjectionRule(config),
            SpringDataSortInjectionRule(config),
            // A04 Insecure Design
            MassAssignmentRule(config),
            // A05 Security Misconfiguration
            SpringCsrfDisabledRule(config),
            PermissiveCorsRule(config),
            InsecureActuatorExposureRule(config),
            SecurityHeadersMissingRule(config),
            ExceptionDetailsExposedRule(config),
            HttpMethodOverrideRule(config),
            KafkaTrustedPackagesWildcardRule(config),
            KafkaInsecureProtocolRule(config),
            SpringSecurityDebugEnabledRule(config),
            H2ConsoleEnabledRule(config),
            SpringActuatorShutdownEnabledRule(config),
            CloudConfigInsecureUriRule(config),
            CrossOriginCredentialsWildcardRule(config),
            SpringBootCookieNotHttpOnlyRule(config),
            SpringBootInsecureFileUploadRule(config),
            // A07 Identification and Authentication Failures
            InsecureRememberMeRule(config),
            HardcodedDatasourcePasswordRule(config),
            SpringBootNoOpPasswordEncoderRule(config),
            SpringBootHardcodedValueDefaultRule(config),
            // A08 Software and Data Integrity Failures
            SpringBootRequestBodyAnyTypeRule(config),
            // A09 Security Logging and Monitoring Failures
            ShowSqlEnabledRule(config),
            SecurityLoggingVerboseRule(config),
            SpringBootExceptionBodyLeakRule(config),
            // A10 Server-Side Request Forgery
            WebClientSSRFRule(config),
            RestTemplateSsrfRule(config),
        )
    )
}

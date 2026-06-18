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
            MissingAuthorizationRule(config.subConfig("MissingAuthorization")),
            OpenRedirectRule(config.subConfig("OpenRedirect")),
            DisabledHttpSecurityRule(config.subConfig("DisabledHttpSecurity")),
            CsrfTokenLeakRule(config.subConfig("CsrfTokenLeak")),
            CoroutineSecurityContextLossRule(config.subConfig("CoroutineSecurityContextLoss")),
            AsyncSecurityContextLossRule(config.subConfig("AsyncSecurityContextLoss")),
            FeignClientInsecureUrlRule(config.subConfig("FeignClientInsecureUrl")),
            UnvalidatedForwardRule(config.subConfig("UnvalidatedForward")),
            PermitAllAdminPathRule(config.subConfig("PermitAllAdminPath")),
            // A02 Cryptographic Failures
            InsecurePasswordEncoderRule(config.subConfig("InsecurePasswordEncoder")),
            WeakBcryptRoundsRule(config.subConfig("WeakBcryptRounds")),
            JwtExpirationMissingRule(config.subConfig("JwtExpirationMissing")),
            JwtSecretInPropertiesRule(config.subConfig("JwtSecretInProperties")),
            OAuth2ClientSecretInPropertiesRule(config.subConfig("OAuth2ClientSecretInProperties")),
            SpringCacheableSensitiveRule(config.subConfig("SpringCacheableSensitive")),
            MissingHttpsRedirectRule(config.subConfig("MissingHttpsRedirect")),
            InsecureRedisConnectionRule(config.subConfig("InsecureRedisConnection")),
            InsecureSmtpConfigRule(config.subConfig("InsecureSmtpConfig")),
            // A03 Injection
            SpelInjectionRule(config.subConfig("SpelInjection")),
            ResponseSplittingRule(config.subConfig("ResponseSplitting")),
            ELInjectionRule(config.subConfig("ELInjection")),
            SpringDataMongoInjectionRule(config.subConfig("SpringDataMongoInjection")),
            ThymeleafSSTIRule(config.subConfig("ThymeleafSSTI")),
            EntityManagerJpqlInjectionRule(config.subConfig("EntityManagerJpqlInjection")),
            SpringDataSortInjectionRule(config.subConfig("SpringDataSortInjection")),
            // A04 Insecure Design
            MassAssignmentRule(config.subConfig("MassAssignment")),
            // A05 Security Misconfiguration
            SpringCsrfDisabledRule(config.subConfig("SpringCsrfDisabled")),
            PermissiveCorsRule(config.subConfig("PermissiveCors")),
            InsecureActuatorExposureRule(config.subConfig("InsecureActuatorExposure")),
            SecurityHeadersMissingRule(config.subConfig("SecurityHeadersMissing")),
            ExceptionDetailsExposedRule(config.subConfig("ExceptionDetailsExposed")),
            HttpMethodOverrideRule(config.subConfig("HttpMethodOverride")),
            KafkaTrustedPackagesWildcardRule(config.subConfig("KafkaTrustedPackagesWildcard")),
            KafkaInsecureProtocolRule(config.subConfig("KafkaInsecureProtocol")),
            SpringSecurityDebugEnabledRule(config.subConfig("SpringSecurityDebugEnabled")),
            H2ConsoleEnabledRule(config.subConfig("H2ConsoleEnabled")),
            SpringActuatorShutdownEnabledRule(config.subConfig("SpringActuatorShutdownEnabled")),
            CloudConfigInsecureUriRule(config.subConfig("CloudConfigInsecureUri")),
            CrossOriginCredentialsWildcardRule(config.subConfig("CrossOriginCredentialsWildcard")),
            SpringBootCookieNotHttpOnlyRule(config.subConfig("SpringBootCookieNotHttpOnly")),
            SpringBootInsecureFileUploadRule(config.subConfig("SpringBootInsecureFileUpload")),
            // A07 Identification and Authentication Failures
            InsecureRememberMeRule(config.subConfig("InsecureRememberMe")),
            HardcodedDatasourcePasswordRule(config.subConfig("HardcodedDatasourcePassword")),
            SpringBootNoOpPasswordEncoderRule(config.subConfig("SpringBootNoOpPasswordEncoder")),
            SpringBootHardcodedValueDefaultRule(config.subConfig("SpringBootHardcodedValueDefault")),
            // A08 Software and Data Integrity Failures
            SpringBootRequestBodyAnyTypeRule(config.subConfig("SpringBootRequestBodyAnyType")),
            // A09 Security Logging and Monitoring Failures
            ShowSqlEnabledRule(config.subConfig("ShowSqlEnabled")),
            SecurityLoggingVerboseRule(config.subConfig("SecurityLoggingVerbose")),
            SpringBootExceptionBodyLeakRule(config.subConfig("SpringBootExceptionBodyLeak")),
            // A10 Server-Side Request Forgery
            WebClientSSRFRule(config.subConfig("WebClientSSRF")),
            RestTemplateSsrfRule(config.subConfig("RestTemplateSsrf")),
        )
    )
}

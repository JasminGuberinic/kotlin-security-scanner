package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.KtorCsrfMissingRule
import com.jasmin.security.detekt.a01.KtorInsecureRedirectRule
import com.jasmin.security.detekt.a01.KtorMissingAuthRule
import com.jasmin.security.detekt.a02.KtorBasicAuthInsecureRule
import com.jasmin.security.detekt.a02.KtorWeakJwtSecretRule
import com.jasmin.security.detekt.a03.KtorExposedOrmInjectionRule
import com.jasmin.security.detekt.a03.KtorSensitiveRouteParamRule
import com.jasmin.security.detekt.a03.KtorXssResponseRule
import com.jasmin.security.detekt.a05.KtorClearTextCookieRule
import com.jasmin.security.detekt.a05.KtorInsecureCookieSessionRule
import com.jasmin.security.detekt.a05.KtorPermissiveCorsRule
import com.jasmin.security.detekt.a05.KtorRateLimitingMissingRule
import com.jasmin.security.detekt.a05.KtorSecurityHeadersMissingRule
import com.jasmin.security.detekt.a05.KtorSessionCookieDomainMissingRule
import com.jasmin.security.detekt.a05.KtorSslRedirectMissingRule
import com.jasmin.security.detekt.a07.KtorHardcodedDatabasePasswordRule
import com.jasmin.security.detekt.a07.KtorHardcodedPasswordComparisonRule
import com.jasmin.security.detekt.a07.KtorHardcodedSecretKeyRule
import com.jasmin.security.detekt.a09.KtorLoggingCredentialsRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

class KtorRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-ktor"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            KtorMissingAuthRule(config.subConfig("KtorMissingAuth")),
            KtorInsecureRedirectRule(config.subConfig("KtorInsecureRedirect")),
            KtorCsrfMissingRule(config.subConfig("KtorCsrfMissing")),
            // A02 Cryptographic Failures
            KtorBasicAuthInsecureRule(config.subConfig("KtorBasicAuthInsecure")),
            KtorWeakJwtSecretRule(config.subConfig("KtorWeakJwtSecret")),
            // A03 Injection
            KtorXssResponseRule(config.subConfig("KtorXssResponse")),
            KtorExposedOrmInjectionRule(config.subConfig("KtorExposedOrmInjection")),
            KtorSensitiveRouteParamRule(config.subConfig("KtorSensitiveRouteParam")),
            // A05 Security Misconfiguration
            KtorInsecureCookieSessionRule(config.subConfig("KtorInsecureCookieSession")),
            KtorPermissiveCorsRule(config.subConfig("KtorPermissiveCors")),
            KtorClearTextCookieRule(config.subConfig("KtorClearTextCookie")),
            KtorSecurityHeadersMissingRule(config.subConfig("KtorSecurityHeadersMissing")),
            KtorSslRedirectMissingRule(config.subConfig("KtorSslRedirectMissing")),
            KtorRateLimitingMissingRule(config.subConfig("KtorRateLimitingMissing")),
            KtorSessionCookieDomainMissingRule(config.subConfig("KtorSessionCookieDomainMissing")),
            // A07 Identification and Authentication Failures
            KtorHardcodedSecretKeyRule(config.subConfig("KtorHardcodedSecretKey")),
            KtorHardcodedPasswordComparisonRule(config.subConfig("KtorHardcodedPasswordComparison")),
            KtorHardcodedDatabasePasswordRule(config.subConfig("KtorHardcodedDatabasePassword")),
            // A09 Security Logging and Monitoring Failures
            KtorLoggingCredentialsRule(config.subConfig("KtorLoggingCredentials")),
        )
    )
}

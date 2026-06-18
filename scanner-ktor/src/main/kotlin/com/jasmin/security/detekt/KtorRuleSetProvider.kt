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
            KtorMissingAuthRule(config),
            KtorInsecureRedirectRule(config),
            KtorCsrfMissingRule(config),
            // A02 Cryptographic Failures
            KtorBasicAuthInsecureRule(config),
            KtorWeakJwtSecretRule(config),
            // A03 Injection
            KtorXssResponseRule(config),
            KtorExposedOrmInjectionRule(config),
            KtorSensitiveRouteParamRule(config),
            // A05 Security Misconfiguration
            KtorInsecureCookieSessionRule(config),
            KtorPermissiveCorsRule(config),
            KtorClearTextCookieRule(config),
            KtorSecurityHeadersMissingRule(config),
            KtorSslRedirectMissingRule(config),
            KtorRateLimitingMissingRule(config),
            KtorSessionCookieDomainMissingRule(config),
            // A07 Identification and Authentication Failures
            KtorHardcodedSecretKeyRule(config),
            KtorHardcodedPasswordComparisonRule(config),
            KtorHardcodedDatabasePasswordRule(config),
            // A09 Security Logging and Monitoring Failures
            KtorLoggingCredentialsRule(config),
        )
    )
}

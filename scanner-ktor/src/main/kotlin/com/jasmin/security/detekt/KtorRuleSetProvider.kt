package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.KtorCsrfMissingRule
import com.jasmin.security.detekt.a01.KtorExposedDeleteAllRule
import com.jasmin.security.detekt.a01.KtorInsecureRedirectRule
import com.jasmin.security.detekt.a01.KtorMissingAuthRule
import com.jasmin.security.detekt.a01.KtorWebSocketNoAuthRule
import com.jasmin.security.detekt.a02.KtorBasicAuthInsecureRule
import com.jasmin.security.detekt.a02.KtorExposedConnectionNotSecureRule
import com.jasmin.security.detekt.a02.KtorWeakJwtSecretRule
import com.jasmin.security.detekt.a03.KtorExposedOrmInjectionRule
import com.jasmin.security.detekt.a03.KtorExposedRawSqlConcatRule
import com.jasmin.security.detekt.a03.KtorFileUploadTraversalRule
import com.jasmin.security.detekt.a03.KtorRespondFileTraversalRule
import com.jasmin.security.detekt.a03.KtorSensitiveRouteParamRule
import com.jasmin.security.detekt.a03.KtorUnvalidatedQueryParamRule
import com.jasmin.security.detekt.a03.KtorXssResponseRule
import com.jasmin.security.detekt.a04.KtorRawCallReceiveRule
import com.jasmin.security.detekt.a05.KtorClearTextCookieRule
import com.jasmin.security.detekt.a05.KtorCorsAnyHeaderRule
import com.jasmin.security.detekt.a05.KtorDevelopmentModeRule
import com.jasmin.security.detekt.a05.KtorExposedSchemaAutoCreateRule
import com.jasmin.security.detekt.a05.KtorForwardedHeaderTrustRule
import com.jasmin.security.detekt.a05.KtorInsecureCookieSessionRule
import com.jasmin.security.detekt.a05.KtorMultipartInsecureUploadRule
import com.jasmin.security.detekt.a05.KtorPermissiveCorsRule
import com.jasmin.security.detekt.a05.KtorRateLimitingMissingRule
import com.jasmin.security.detekt.a05.KtorSecurityHeadersMissingRule
import com.jasmin.security.detekt.a05.KtorSessionCookieDomainMissingRule
import com.jasmin.security.detekt.a05.KtorSslRedirectMissingRule
import com.jasmin.security.detekt.a07.KtorHardcodedDatabasePasswordRule
import com.jasmin.security.detekt.a07.KtorHardcodedPasswordComparisonRule
import com.jasmin.security.detekt.a07.KtorHardcodedSecretKeyRule
import com.jasmin.security.detekt.a08.KtorInsecureContentNegotiationRule
import com.jasmin.security.detekt.a09.KtorLoggingCredentialsRule
import com.jasmin.security.detekt.a09.KtorStatusPageLeakDetailsRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

class KtorRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-ktor"

    override fun instance(config: Config): RuleSet {
        val rules = listOf(
            // A01 Broken Access Control
            KtorMissingAuthRule(config),
            KtorInsecureRedirectRule(config),
            KtorCsrfMissingRule(config),
            KtorExposedDeleteAllRule(config),
            KtorWebSocketNoAuthRule(config),
            // A02 Cryptographic Failures
            KtorBasicAuthInsecureRule(config),
            KtorWeakJwtSecretRule(config),
            KtorExposedConnectionNotSecureRule(config),
            // A03 Injection
            KtorXssResponseRule(config),
            KtorExposedOrmInjectionRule(config),
            KtorExposedRawSqlConcatRule(config),
            KtorSensitiveRouteParamRule(config),
            KtorFileUploadTraversalRule(config),
            KtorUnvalidatedQueryParamRule(config),
            KtorRespondFileTraversalRule(config),
            // A04 Insecure Design
            KtorRawCallReceiveRule(config),
            // A05 Security Misconfiguration
            KtorExposedSchemaAutoCreateRule(config),
            KtorDevelopmentModeRule(config),
            KtorCorsAnyHeaderRule(config),
            KtorInsecureCookieSessionRule(config),
            KtorPermissiveCorsRule(config),
            KtorClearTextCookieRule(config),
            KtorSecurityHeadersMissingRule(config),
            KtorSslRedirectMissingRule(config),
            KtorRateLimitingMissingRule(config),
            KtorSessionCookieDomainMissingRule(config),
            KtorForwardedHeaderTrustRule(config),
            KtorMultipartInsecureUploadRule(config),
            // A07 Identification and Authentication Failures
            KtorHardcodedSecretKeyRule(config),
            KtorHardcodedPasswordComparisonRule(config),
            KtorHardcodedDatabasePasswordRule(config),
            // A08 Software and Data Integrity Failures
            KtorInsecureContentNegotiationRule(config),
            // A09 Security Logging and Monitoring Failures
            KtorLoggingCredentialsRule(config),
            KtorStatusPageLeakDetailsRule(config),
        )
        return RuleSet(ruleSetId, rules)
    }
}

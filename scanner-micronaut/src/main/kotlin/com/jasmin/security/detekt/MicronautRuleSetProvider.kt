package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.MicronautAnonymousAccessRule
import com.jasmin.security.detekt.a01.MicronautCacheableSensitiveRule
import com.jasmin.security.detekt.a01.MicronautMissingSecuredRule
import com.jasmin.security.detekt.a01.MicronautRetryOnAuthRule
import com.jasmin.security.detekt.a01.MicronautWebSocketNoAuthRule
import com.jasmin.security.detekt.a02.MicronautGrpcInsecureRule
import com.jasmin.security.detekt.a02.MicronautInsecureHttpClientRule
import com.jasmin.security.detekt.a03.MicronautSensitiveQueryParamRule
import com.jasmin.security.detekt.a04.MicronautBodyAnyTypeRule
import com.jasmin.security.detekt.a05.MicronautInsecureCookieRule
import com.jasmin.security.detekt.a05.MicronautManagementEndpointInsecureRule
import com.jasmin.security.detekt.a07.MicronautHardcodedSecretRule
import com.jasmin.security.detekt.a09.MicronautExceptionMessageLeakRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

class MicronautRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-micronaut"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            MicronautMissingSecuredRule(config),
            MicronautWebSocketNoAuthRule(config),
            MicronautCacheableSensitiveRule(config),
            MicronautRetryOnAuthRule(config),
            MicronautAnonymousAccessRule(config),
            // A02 Cryptographic Failures
            MicronautInsecureHttpClientRule(config),
            MicronautGrpcInsecureRule(config),
            // A03 Injection
            MicronautSensitiveQueryParamRule(config),
            // A04 Insecure Design
            MicronautBodyAnyTypeRule(config),
            // A05 Security Misconfiguration
            MicronautManagementEndpointInsecureRule(config),
            MicronautInsecureCookieRule(config),
            // A07 Identification and Authentication Failures
            MicronautHardcodedSecretRule(config),
            // A09 Security Logging and Monitoring Failures
            MicronautExceptionMessageLeakRule(config),
        )
    )
}

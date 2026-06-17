package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.KtorMissingAuthRule
import com.jasmin.security.detekt.a05.KtorInsecureCookieSessionRule
import com.jasmin.security.detekt.a05.KtorPermissiveCorsRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Ktor-specific security rules.
 * Catches missing authentication on routes, insecure session storage,
 * and permissive CORS configuration.
 */
class KtorRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-ktor"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            KtorMissingAuthRule(config.subConfig("KtorMissingAuth")),
            // A05 Security Misconfiguration
            KtorInsecureCookieSessionRule(config.subConfig("KtorInsecureCookieSession")),
            KtorPermissiveCorsRule(config.subConfig("KtorPermissiveCors")),
        )
    )
}

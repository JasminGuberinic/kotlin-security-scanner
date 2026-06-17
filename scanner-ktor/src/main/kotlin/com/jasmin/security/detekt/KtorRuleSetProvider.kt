package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.KtorInsecureRedirectRule
import com.jasmin.security.detekt.a01.KtorMissingAuthRule
import com.jasmin.security.detekt.a02.KtorBasicAuthInsecureRule
import com.jasmin.security.detekt.a03.KtorXssResponseRule
import com.jasmin.security.detekt.a05.KtorClearTextCookieRule
import com.jasmin.security.detekt.a05.KtorInsecureCookieSessionRule
import com.jasmin.security.detekt.a05.KtorPermissiveCorsRule
import com.jasmin.security.detekt.a07.KtorHardcodedPasswordComparisonRule
import com.jasmin.security.detekt.a07.KtorHardcodedSecretKeyRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

/**
 * Ktor-specific security rules.
 * Catches missing authentication on routes, insecure session storage,
 * open redirects, XSS, and hardcoded secrets.
 */
class KtorRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-ktor"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            KtorMissingAuthRule(config.subConfig("KtorMissingAuth")),
            KtorInsecureRedirectRule(config.subConfig("KtorInsecureRedirect")),
            // A02 Cryptographic Failures
            KtorBasicAuthInsecureRule(config.subConfig("KtorBasicAuthInsecure")),
            // A03 Injection
            KtorXssResponseRule(config.subConfig("KtorXssResponse")),
            // A05 Security Misconfiguration
            KtorInsecureCookieSessionRule(config.subConfig("KtorInsecureCookieSession")),
            KtorPermissiveCorsRule(config.subConfig("KtorPermissiveCors")),
            KtorClearTextCookieRule(config.subConfig("KtorClearTextCookie")),
            // A07 Identification and Authentication Failures
            KtorHardcodedSecretKeyRule(config.subConfig("KtorHardcodedSecretKey")),
            KtorHardcodedPasswordComparisonRule(config.subConfig("KtorHardcodedPasswordComparison")),
        )
    )
}

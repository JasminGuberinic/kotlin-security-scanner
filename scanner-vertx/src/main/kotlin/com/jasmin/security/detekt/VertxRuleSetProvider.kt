package com.jasmin.security.detekt

import com.jasmin.security.detekt.a01.VertxEventBusBridgeOpenRule
import com.jasmin.security.detekt.a02.VertxJwtNoneAlgorithmRule
import com.jasmin.security.detekt.a02.VertxTrustAllCertsRule
import com.jasmin.security.detekt.a03.VertxStaticHandlerRootFsRule
import com.jasmin.security.detekt.a05.VertxBodyHandlerNoLimitRule
import com.jasmin.security.detekt.a05.VertxCookieNoHttpOnlyRule
import com.jasmin.security.detekt.a05.VertxCorsWildcardRule
import com.jasmin.security.detekt.a05.VertxInsecureCookieRule
import com.jasmin.security.detekt.a05.VertxSessionCookieInsecureRule
import com.jasmin.security.detekt.a05.VertxStaticHandlerDirectoryListingRule
import com.jasmin.security.detekt.a07.VertxHardcodedJwtSecretRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.RuleSet
import io.gitlab.arturbosch.detekt.api.RuleSetProvider

class VertxRuleSetProvider : RuleSetProvider {

    override val ruleSetId = "security-vertx"

    override fun instance(config: Config): RuleSet = RuleSet(
        ruleSetId,
        listOf(
            // A01 Broken Access Control
            VertxEventBusBridgeOpenRule(config),
            // A02 Cryptographic Failures
            VertxTrustAllCertsRule(config),
            VertxJwtNoneAlgorithmRule(config),
            // A03 Injection
            VertxStaticHandlerRootFsRule(config),
            // A05 Security Misconfiguration
            VertxCorsWildcardRule(config),
            VertxBodyHandlerNoLimitRule(config),
            VertxInsecureCookieRule(config),
            VertxCookieNoHttpOnlyRule(config),
            VertxSessionCookieInsecureRule(config),
            VertxStaticHandlerDirectoryListingRule(config),
            // A07 Identification and Authentication Failures
            VertxHardcodedJwtSecretRule(config),
        )
    )
}

package com.jasmin.security.detekt.a05

import com.jasmin.security.detekt.core.DetectionPatterns
import com.jasmin.security.detekt.core.SecurityRule
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression

/**
 * OWASP A05 — Security Misconfiguration (Insecure Cookie)
 * FindSecBugs: INSECURE_COOKIE
 *
 * Flags NewCookie construction that omits the Secure flag, allowing session cookies
 * to be transmitted over plain HTTP. The 2-argument constructor never sets Secure or
 * HttpOnly. The 8-argument constructor permits explicit secure=false.
 *
 * Compliant:
 *   NewCookie.Builder("session").value(token).secure(true).httpOnly(true).build()
 *
 * Non-compliant:
 *   NewCookie("session", token)                     // 2-arg: no Secure/HttpOnly
 *   NewCookie("s", v, "/", null, 1, "", -1, false)  // 8-arg: secure=false
 */
class InsecureCookieRule(config: Config) : SecurityRule(config) {

    override val issue = Issue(
        id = "InsecureCookie",
        severity = Severity.Security,
        description = "NewCookie without Secure flag — session cookies must be set Secure and HttpOnly",
        debt = Debt.TWENTY_MINS,
    )

    @Suppress("ReturnCount", "MagicNumber")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)
        if (expression.calleeExpression?.text != DetectionPatterns.NEW_COOKIE) return
        val args = expression.valueArguments
        when (args.size) {
            2 -> reportAt(
                expression,
                "NewCookie(name, value) sets no Secure or HttpOnly flags — use NewCookie.Builder instead",
            )
            8 -> {
                val secureArg = args[7].getArgumentExpression()?.text
                if (secureArg == "false") {
                    reportAt(
                        expression,
                        "NewCookie(…, secure=false) disables the Secure flag — set true for session cookies",
                    )
                }
            }
        }
    }
}

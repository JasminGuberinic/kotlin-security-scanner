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
 * Flags NewCookie construction that omits or disables the Secure flag, allowing
 * session cookies to be transmitted over plain HTTP.
 *
 * The standard JAX-RS / Jakarta constructor is:
 *   NewCookie(name, value, path, domain, comment, maxAge, secure, httpOnly)
 * so `secure` is positional index 6 and `httpOnly` index 7. The 6-arg and 7-arg
 * overloads `NewCookie(name, value, path, domain, comment, maxAge[, secure])`
 * default `secure` to false. The 2-argument constructor never sets Secure or HttpOnly.
 *
 * Compliant:
 *   NewCookie.Builder("session").value(token).secure(true).httpOnly(true).build()
 *   NewCookie("s", v, "/", null, "", 3600, true, false)  // secure=true at index 6
 *
 * Non-compliant:
 *   NewCookie("session", token)                          // 2-arg: no Secure/HttpOnly
 *   NewCookie("s", v, "/", null, "", 3600, false, true)  // 8-arg: secure=false
 *   NewCookie("s", v, "/", "example.com", "", 3600)      // 6-arg: secure defaults to false
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
            // 6-arg / 7-arg: NewCookie(name, value, path, domain, comment, maxAge[, secure]).
            // The 6-arg form has no secure parameter (defaults to false); the 7-arg form
            // carries secure at index 6.
            6, 7 -> {
                val secureArg = if (args.size == 7) args[6].getArgumentExpression()?.text else null
                if (secureArg != "true") {
                    reportAt(
                        expression,
                        "NewCookie(…) leaves the Secure flag unset (defaults to false) — set secure=true",
                    )
                }
            }
            // 8-arg: NewCookie(name, value, path, domain, comment, maxAge, secure, httpOnly).
            // `secure` is index 6, `httpOnly` is index 7.
            8 -> {
                val secureArg = args[6].getArgumentExpression()?.text
                if (secureArg != "true") {
                    reportAt(
                        expression,
                        "NewCookie(…, secure=false) disables the Secure flag — set true for session cookies",
                    )
                }
            }
        }
    }
}

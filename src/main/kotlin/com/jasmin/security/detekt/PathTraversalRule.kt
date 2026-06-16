package com.jasmin.security.detekt

import io.gitlab.arturbosch.detekt.api.CodeSmell
import io.gitlab.arturbosch.detekt.api.Config
import io.gitlab.arturbosch.detekt.api.Debt
import io.gitlab.arturbosch.detekt.api.Entity
import io.gitlab.arturbosch.detekt.api.Issue
import io.gitlab.arturbosch.detekt.api.Rule
import io.gitlab.arturbosch.detekt.api.Severity
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtStringTemplateExpression

// FindSecBugs: PATH_TRAVERSAL_IN, PATH_TRAVERSAL_OUT — OWASP A03
class PathTraversalRule(config: Config = Config.empty) : Rule(config) {

    override val issue = Issue(
        id = "PathTraversal",
        severity = Severity.Security,
        description = "File path constructed with a variable — validate and sanitize path input to prevent " +
            "directory traversal attacks (OWASP A03)",
        debt = Debt.TWENTY_MINS
    )

    private val fileConstructors = setOf("File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter")
    private val pathMethods = setOf("get", "of", "resolve")

    @Suppress("ReturnCount")
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)

        val calleeName = expression.calleeExpression?.text ?: return
        val args = expression.valueArguments

        if (args.isEmpty()) return

        val firstArg = args.first().getArgumentExpression() ?: return

        // Skip if argument is a plain string literal (no variable interpolation)
        if (firstArg is KtStringTemplateExpression && !firstArg.hasInterpolation()) return

        if (calleeName in fileConstructors) {
            report(
                CodeSmell(
                    issue,
                    Entity.from(expression),
                    "'$calleeName' called with a non-literal path — validate input to prevent path traversal"
                )
            )
            return
        }

        // Catch Paths.get(userInput) / Path.of(userInput)
        if (calleeName in pathMethods) {
            val parentText = expression.parent?.text ?: return
            if (parentText.startsWith("Paths.") || parentText.startsWith("Path.")) {
                report(
                    CodeSmell(
                        issue,
                        Entity.from(expression),
                        "'$calleeName' called with a non-literal path — validate input to prevent path traversal"
                    )
                )
            }
        }
    }
}

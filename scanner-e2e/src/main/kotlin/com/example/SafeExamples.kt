package com.example

// ── Negative fixtures ─────────────────────────────────────────────────────────
//
// Secure equivalents of the patterns the new rules flag. The e2e coverage check
// asserts that scanning this file produces ZERO findings — proving the rules do not
// fire on correct code (no false positives).

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.regex.Pattern
import java.util.zip.ZipEntry

// Secrets — loaded from the environment, never hardcoded.
val safeGoogleKey: String? = System.getenv("GOOGLE_API_KEY")
val safeSlackToken: String? = System.getenv("SLACK_TOKEN")
val safeGithubToken: String? = System.getenv("GITHUB_TOKEN")
val safeStripeKey: String? = System.getenv("STRIPE_SECRET_KEY")
val safeJdbcUrl = "jdbc:postgresql://db.internal:5432/app" // no embedded credentials

fun safeSslContext(): javax.net.ssl.SSLContext =
    javax.net.ssl.SSLContext.getInstance("TLSv1.3")

fun safeExtract(dir: Path, entry: ZipEntry): Path {
    val rawName: String = entry.name
    val cleanName = rawName.substringAfterLast('/') // strip any directory components
    val target = dir.resolve(cleanName).normalize()
    require(target.startsWith(dir)) { "Zip Slip blocked" }
    return target
}

fun safeRegex(): Pattern = Pattern.compile("^[a-z0-9]+$") // fixed pattern

fun safeLogging(request: Map<String, String>, log: org.slf4j.Logger) {
    log.info("path={}", request["path"]) // parameterized, no interpolation
}

fun safePerms(): java.util.Set<java.nio.file.attribute.PosixFilePermission> =
    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------") // owner only

fun safeTemp(): Path = Files.createTempFile("upload", ".tmp") // unpredictable, owner-only

fun safeOwnerOnlyWritable(file: File) {
    file.setWritable(true, true) // ownerOnly = true
}

// Spring Security DSL — protections kept enabled.
fun safeFrameOptions(http: Any) {
    http.headers { frameOptions { sameOrigin() } }
}

fun safeSessionFixation(http: Any) {
    http.sessionManagement { sessionFixation { migrateSession() } }
}

// WebFlux (reactive) — done correctly.
fun safeReactiveMe(): reactor.core.publisher.Mono<String> =
    ReactiveSecurityContextHolder.getContext().map { it.authentication.name }

fun safeReactiveSecurity(http: Any) {
    http.authorizeExchange { it.anyExchange().authenticated() }
}

fun safeReactiveHandler(repo: Any, id: Long): reactor.core.publisher.Mono<String> =
    repo.findById(id).map { it.toString() } // composed, no block()

// Vert.x — done correctly.
fun safeVertxClient() =
    io.vertx.ext.web.client.WebClientOptions().setTrustAll(false).setVerifyHost(true)

fun safeVertxCors() =
    io.vertx.ext.web.handler.CorsHandler.create().addOrigin("https://app.example.com")

fun safeVertxBody(router: io.vertx.ext.web.Router) =
    router.route().handler(io.vertx.ext.web.handler.BodyHandler.create().setBodyLimit(10485760))

fun safeVertxBridge() =
    io.vertx.ext.bridge.PermittedOptions().setAddress("news.updates")

fun safeVertxCookie(id: String) =
    io.vertx.core.http.Cookie.cookie("session", id).setSecure(true)

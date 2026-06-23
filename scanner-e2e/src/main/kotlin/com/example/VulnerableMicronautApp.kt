package com.example

import com.nimbusds.jose.crypto.MACSigner
import io.micronaut.context.annotation.Value
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Delete
import io.micronaut.http.annotation.Error
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.QueryValue
import io.micronaut.http.client.annotation.Client
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import java.net.URI

// ── A01 Broken Access Control ─────────────────────────────────────────────────

@Controller("/admin")
class AdminController {
    // VULNERABLE: no @Secured [MicronautMissingSecured, CWE-285]
    @Get("/users")
    fun listUsers(): List<String> = emptyList()

    // VULNERABLE: no @Secured on Delete [MicronautMissingSecured, CWE-285]
    @Delete("/users/{id}")
    fun deleteUser(id: Long): HttpResponse<*> = HttpResponse.ok<Any>()

    // SAFE: has @Secured
    @Get("/profile")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    fun profile(): String = "profile"
}

// VULNERABLE: open redirect via dynamic URI [MicronautOpenRedirect, CWE-601]
@Controller("/redirect")
class RedirectController {
    @Get
    fun redirect(@QueryValue url: String): HttpResponse<*> =
        HttpResponse.seeOther<Any>(URI(url))
}

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

// VULNERABLE: @Client over plain HTTP [MicronautInsecureHttpClient, CWE-319]
@Client("http://payment-service")
interface PaymentClient

// VULNERABLE: MACSigner with hardcoded secret [MicronautHardcodedJwtSecret, CWE-798]
class MicronautJwtFactory {
    fun buildSigner() = MACSigner("hardcoded-secret-key-256-bits-long!!")
}

// ── A03 Injection ─────────────────────────────────────────────────────────────

// VULNERABLE: password in URL query param [MicronautSensitiveQueryParam, CWE-598]
@Controller("/auth")
class AuthController {
    @Post("/login")
    fun login(@QueryValue password: String): HttpResponse<*> = HttpResponse.ok<Any>()
}

// ── A04 Insecure Design ───────────────────────────────────────────────────────

// VULNERABLE: @Body typed as Any [MicronautBodyAnyType, CWE-20]
@Controller("/data")
class DataController {
    @Post
    fun receive(@Body body: Any): HttpResponse<*> = HttpResponse.ok(body)
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

// VULNERABLE: CORS wildcard [MicronautCorsAllowAllOrigins, CWE-942]
class MicronautCorsConfig {
    fun configure() {
        allowedOrigins("*")
    }
}

// ── A07 Identification and Authentication Failures ────────────────────────────

// VULNERABLE: @Value with hardcoded default for jwt secret [MicronautHardcodedSecret, CWE-798]
@Controller("/config")
class ConfigController {
    @Value("\${jwt.secret:super-secret-key-hardcoded}")
    lateinit var jwtSecret: String
}

// ── A09 Security Logging and Monitoring Failures ──────────────────────────────

// VULNERABLE: @Error handler leaks exception.message [MicronautExceptionMessageLeak, CWE-209]
@Controller("/errors")
class GlobalErrorHandler {
    @Error
    fun handleError(e: Exception): HttpResponse<String> =
        HttpResponse.serverError(e.message)
}

// ── New Micronaut rules ───────────────────────────────────────────────────────

// VULNERABLE: WebSocket endpoint without @Secured [MicronautWebSocketNoAuth, CWE-285]
@io.micronaut.websocket.annotation.ServerWebSocket("/notifications/{token}")
class NotificationHandler {
    @io.micronaut.websocket.annotation.OnMessage
    fun onMessage(message: String) {}
}

// VULNERABLE: @Cacheable on @Secured method — cross-user cache leak [MicronautCacheableSensitive, CWE-285]
@Controller("/users")
@Secured(SecurityRule.IS_AUTHENTICATED)
class UserController {
    @Get("/{id}")
    @io.micronaut.cache.annotation.Cacheable("user-profiles")
    fun getProfile(id: Long): String = "profile-$id"
}

// VULNERABLE: Management endpoint with unsecured @Read [MicronautManagementEndpointInsecure, CWE-284]
@io.micronaut.management.endpoint.annotation.Endpoint("app-info")
class AppInfoEndpoint {
    @io.micronaut.management.endpoint.annotation.Read
    fun info(): Map<String, Any> = mapOf("version" to "1.0", "db" to System.getenv("DB_URL"))
}

// VULNERABLE: @Retryable on authentication method [MicronautRetryOnAuth, CWE-307]
class LoginService {
    @io.micronaut.retry.annotation.Retryable
    fun authenticate(username: String, password: String): Boolean = false
}

// VULNERABLE: gRPC channel with usePlaintext() [MicronautGrpcInsecure, CWE-319]
class GrpcClientFactory {
    fun paymentChannel() = io.grpc.ManagedChannelBuilder
        .forAddress("payment-service", 8080)
        .usePlaintext()
        .build()
}

// VULNERABLE: anonymous access on a state-changing endpoint [MicronautAnonymousAccess, CWE-285]
@io.micronaut.http.annotation.Controller("/anon-admin")
class AnonymousAdminController {
    @io.micronaut.http.annotation.Delete("/users/{id}")
    @io.micronaut.security.annotation.Secured(io.micronaut.security.rules.SecurityRule.IS_ANONYMOUS)
    fun delete(id: Long) {}
}

// VULNERABLE: cookie marked secure(false) [MicronautInsecureCookie, CWE-614]
fun buildSessionCookie(id: String) =
    io.micronaut.http.cookie.Cookie.of("SESSION", id).secure(false)

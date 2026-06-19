package com.example

import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.QueryParam
import javax.ws.rs.core.NewCookie
import javax.ws.rs.core.Response
import java.net.URI

// ── A01 Broken Access Control ─────────────────────────────────────────────────

@Path("/api")
class UserResource {
    // VULNERABLE: no @RolesAllowed [DropwizardMissingAuth, CWE-285]
    @GET
    @Path("/users")
    fun getUsers(): Response = Response.ok().build()

    @POST
    @Path("/users/delete")
    fun deleteUser(id: String): Response = Response.ok().build()
}

@Path("/redirect")
class RedirectResource {
    @GET
    fun redirect(@QueryParam("to") redirectTo: String): Response {
        // VULNERABLE: open redirect — user controls URI [DropwizardOpenRedirect, CWE-601]
        return Response.seeOther(URI(redirectTo)).build()
    }
}

@Path("/page")
class HtmlResource {
    // VULNERABLE: produces HTML with user content — reflected XSS [DropwizardXssResponse, CWE-79]
    @GET
    @javax.ws.rs.Produces("text/html")
    fun page(@QueryParam("name") name: String): Response =
        Response.ok("<h1>Hello $name</h1>").build()
}

class CreateRequest(val name: String = "")

@Path("/items")
class ItemResource {
    // VULNERABLE: no @Valid on request body [DropwizardMissingBeanValidation, CWE-20]
    @POST
    fun create(req: CreateRequest): Response = Response.ok().build()
}

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

class TlsConfiguration {
    fun configureTls() {
        val tlsConfig = io.dropwizard.jetty.HttpsConnectorFactory()
        // VULNERABLE: deprecated TLS version [InsecureTlsProtocol, CWE-326]
        tlsConfig.setSupportedProtocols("TLSv1.0")
    }
}

class JwtFilterConfig {
    // VULNERABLE: JWT secret hardcoded in setSecretProvider [DropwizardUnencryptedJwtSecret, CWE-798]
    fun buildFilter() {
        io.dropwizard.auth.jwt.JwtAuthFilter.Builder<Any>()
            .setSecretProvider("hardcoded-jwt-secret-key-2024")
            .buildAuthFilter()
    }
}

// ── A03 Injection ─────────────────────────────────────────────────────────────

interface JdbiUserDao {
    // VULNERABLE: @SqlQuery with interpolated string [DropwizardJdbiSqlInjection, CWE-89]
    @org.jdbi.v3.sqlobject.statement.SqlQuery("SELECT * FROM users WHERE username = '$username'")
    fun findByUsername(username: String): List<Any>

    @org.jdbi.v3.sqlobject.statement.SqlUpdate("UPDATE users SET active = true WHERE id = $id")
    fun activate(id: Long)
}

class ELValidator : javax.validation.ConstraintValidator<javax.validation.constraints.NotNull, String> {
    override fun initialize(constraintAnnotation: javax.validation.constraints.NotNull) {}
    override fun isValid(value: String, context: javax.validation.ConstraintValidatorContext): Boolean {
        // VULNERABLE: user value directly in EL template [DropwizardSelfValidatingEL, CWE-94]
        context.buildConstraintViolationWithTemplate(value).addConstraintViolation()
        return false
    }
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

@Path("/session")
class SessionResource {
    @GET
    fun createSession(): Response {
        // VULNERABLE: cookie without Secure/HttpOnly [InsecureCookie, CWE-614]
        val cookie = NewCookie("SESSION", "abc123")
        return Response.ok().cookie(cookie).build()
    }
}

// ── A07 Identification and Authentication Failures ────────────────────────────

class AppConfiguration {
    // VULNERABLE: hardcoded credentials [HardcodedCredentials, CWE-798]
    val databasePassword = "hardcodedDbPass!"
    // VULNERABLE: hardcoded API token [DropwizardHardcodedToken, CWE-798]
    val apiKey = "sk-prod-abc123def456ghi789"
}

// ── A08 Software and Data Integrity ──────────────────────────────────────────

fun configureJackson(): com.fasterxml.jackson.databind.ObjectMapper {
    val mapper = com.fasterxml.jackson.databind.ObjectMapper()
    // VULNERABLE: unsafe deserialization [JacksonUnsafeDeserialization, CWE-502]
    mapper.enableDefaultTyping(com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping.NON_FINAL)
    return mapper
}

// ── A09 Security Logging ──────────────────────────────────────────────────────

class AuditLogger {
    private val log = org.slf4j.LoggerFactory.getLogger(AuditLogger::class.java)

    fun logPayment(cardNumber: String, cvv: String, amount: Double) {
        // VULNERABLE: payment data in logs [SensitiveDataLogging, CWE-532]
        log.info("Payment: card=$cardNumber cvv=$cvv amount=$amount")
    }
}

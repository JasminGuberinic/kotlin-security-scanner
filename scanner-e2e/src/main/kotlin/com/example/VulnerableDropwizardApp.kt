package com.example

import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.core.NewCookie
import javax.ws.rs.core.Response

// ── A01 Broken Access Control ─────────────────────────────────────────────────

@Path("/api")
class UserResource {
    // VULNERABLE: no @RolesAllowed — public access to user management [CWE-285]
    @GET
    @Path("/users")
    fun getUsers(): Response = Response.ok().build()

    @POST
    @Path("/users/delete")
    fun deleteUser(id: String): Response = Response.ok().build()
}

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

fun configureTls(): javax.net.ssl.SSLContext {
    // VULNERABLE: TLSv1.0 is deprecated and broken [CWE-326]
    val ctx = javax.net.ssl.SSLContext.getInstance("TLSv1")
    return ctx
}

class JwtConfig {
    // VULNERABLE: JWT secret stored unencrypted in config [CWE-798]
    val jwtSecret = "my-super-secret-jwt-key-2024"
}

// ── A03 Injection ─────────────────────────────────────────────────────────────

class UserDao(private val jdbi: org.jdbi.v3.core.Jdbi) {
    fun findByUsername(username: String): Any? {
        // VULNERABLE: JDBI SQL injection via string concatenation [CWE-89]
        return jdbi.withHandle<Any, Exception> { handle ->
            handle.createQuery("SELECT * FROM users WHERE username = '" + username + "'")
                .mapToMap()
                .findFirst()
                .orElse(null)
        }
    }
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

@Path("/session")
class SessionResource {
    @GET
    fun createSession(): Response {
        // VULNERABLE: cookie missing Secure and HttpOnly flags [CWE-614]
        val cookie = NewCookie("SESSION", "abc123")
        return Response.ok().cookie(cookie).build()
    }
}

// ── A07 Identification and Authentication Failures ────────────────────────────

class AppConfiguration {
    // VULNERABLE: hardcoded database password [CWE-798]
    val databasePassword = "hardcodedDbPass!"
    val adminToken = "Bearer eyJhbGciOiJub25lIn0.admin.token"
}

// ── A08 Software and Data Integrity ──────────────────────────────────────────

fun configureJackson(): com.fasterxml.jackson.databind.ObjectMapper {
    val mapper = com.fasterxml.jackson.databind.ObjectMapper()
    // VULNERABLE: enables polymorphic type handling — deserialization gadget risk [CWE-502]
    mapper.enableDefaultTyping(com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping.NON_FINAL)
    return mapper
}

// ── A09 Security Logging ──────────────────────────────────────────────────────

class AuditLogger {
    private val log = org.slf4j.LoggerFactory.getLogger(AuditLogger::class.java)

    fun logPayment(cardNumber: String, cvv: String, amount: Double) {
        // VULNERABLE: PCI-sensitive data written to logs [CWE-532]
        log.info("Payment processed: card=${'$'}cardNumber cvv=${'$'}cvv amount=${'$'}amount")
    }
}

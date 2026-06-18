package com.example

import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.core.Response

// ── A01 Broken Access Control ─────────────────────────────────────────────────

@Path("/admin")
class AdminResource {
    // VULNERABLE: no @RolesAllowed — unauthenticated access to admin endpoint [CWE-285]
    @GET
    @Path("/users")
    fun listUsers(): Response = Response.ok(listOf("alice", "bob")).build()

    // VULNERABLE: @PermitAll on sensitive financial endpoint [CWE-285]
    @GET
    @Path("/transactions")
    @javax.annotation.security.PermitAll
    fun getTransactions(): Response = Response.ok().build()
}

// ── A03 Injection ─────────────────────────────────────────────────────────────

class UserRepository {
    fun findByName(name: String) {
        // VULNERABLE: Panache raw query with string concatenation [CWE-89]
        io.quarkus.hibernate.orm.panache.PanacheQuery::class
        val users = UserEntity.find("name = '" + name + "'")
    }

    fun findByRole(role: String) {
        // VULNERABLE: native query injection [CWE-89]
        val em = javax.persistence.Persistence.createEntityManagerFactory("default").createEntityManager()
        em.createNativeQuery("SELECT * FROM users WHERE role = '${'$'}{role}'").resultList
    }
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

// VULNERABLE: permissive CORS allows any origin [CWE-942]
// In application.properties this would be: quarkus.http.cors.origins=*
// Represented here as a config class
class CorsConfig {
    val allowedOrigins = "*"
    val corsEnabled = true
}

// ── A07 Identification and Authentication Failures ────────────────────────────

class AppConfig {
    // VULNERABLE: hardcoded secret in @ConfigProperty default value [CWE-798]
    @org.eclipse.microprofile.config.inject.ConfigProperty(name = "jwt.secret", defaultValue = "hardcoded-jwt-secret-key")
    lateinit var jwtSecret: String

    @org.eclipse.microprofile.config.inject.ConfigProperty(name = "db.password", defaultValue = "prodPassword!")
    lateinit var dbPassword: String
}

// ── A09 Security Logging ──────────────────────────────────────────────────────

class AuthService {
    private val log = org.jboss.logging.Logger.getLogger(AuthService::class.java)

    fun login(username: String, password: String) {
        // VULNERABLE: password appears in log output [CWE-532]
        log.infof("User login: username=%s password=%s", username, password)
    }
}

// ── A08 Software and Data Integrity ──────────────────────────────────────────

class DeserializationService {
    // VULNERABLE: Jsonb deserialization with Object type allows any class [CWE-502]
    fun deserialize(json: String): Any {
        val jsonb = javax.json.bind.JsonbBuilder.create()
        return jsonb.fromJson(json, Object::class.java)
    }
}

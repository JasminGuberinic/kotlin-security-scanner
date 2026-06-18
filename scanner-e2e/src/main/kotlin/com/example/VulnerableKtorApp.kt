package com.example

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*

// ── A01 Broken Access Control ─────────────────────────────────────────────────

fun Application.configureRoutes() {
    routing {
        // VULNERABLE: /admin route with no authenticate{} wrapper [CWE-285]
        get("/admin/users") {
            call.respondText("admin data")
        }

        post("/admin/delete") {
            call.respondText("deleted")
        }
    }
}

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

fun configureJwt() {
    // VULNERABLE: weak hardcoded JWT secret [CWE-798]
    JWT.require(Algorithm.HMAC256("secret")).build()
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

fun Application.configureCors() {
    install(CORS) {
        // VULNERABLE: any host allowed — CORS wildcard [CWE-942]
        anyHost()
    }
}

fun Application.configureSessions() {
    install(Sessions) {
        // VULNERABLE: cookie session with no domain restriction [CWE-565]
        cookie<UserSession>("SESSION") {
            cookie.path = "/"
            // missing: cookie.domain = "yourdomain.com"
            // missing: cookie.secure = true
        }
    }
}

fun Application.configureHeaders() {
    // VULNERABLE: DefaultHeaders not installed — no security headers [CWE-693]
    routing {
        get("/api/data") {
            call.respondText("sensitive data")
        }
    }
    // missing: install(DefaultHeaders) { ... }
}

// ── A07 Identification and Authentication Failures ────────────────────────────

object DbConfig {
    // VULNERABLE: hardcoded database password [CWE-798]
    fun connectToDatabase() {
        org.jetbrains.exposed.sql.Database.connect(
            url = "jdbc:postgresql://localhost/mydb",
            driver = "org.postgresql.Driver",
            user = "admin",
            password = "prodDbPassword123!"
        )
    }
}

// ── A09 Security Logging ──────────────────────────────────────────────────────

fun Application.configureLogging() {
    routing {
        post("/login") {
            val password = call.parameters["password"]
            val username = call.parameters["username"]
            // VULNERABLE: logs credentials to application log [CWE-532]
            application.log.info("Login: user=${'$'}username password=${'$'}password")
        }
    }
}

data class UserSession(val userId: String)

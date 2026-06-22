package com.example

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.basic
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.plugins.defaultheaders.DefaultHeaders
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import org.jetbrains.exposed.sql.Database

data class UserSession(val userId: String)

// ── A01 Broken Access Control ─────────────────────────────────────────────────

fun Application.configureRoutes() {
    // VULNERABLE: routing without authenticate block [KtorMissingAuth, CWE-285]
    routing {
        get("/admin/users") { call.respondText("admin data") }
        post("/admin/delete") { call.respondText("deleted") }

        // VULNERABLE: login endpoint without rate limiting [KtorRateLimitingMissing, CWE-307]
        post("/login") {
            val username = call.parameters["username"]
            val password = call.parameters["password"]
            // VULNERABLE: credentials logged [KtorLoggingCredentials / SensitiveDataLogging, CWE-532]
            application.log.info("Login: user=$username password=$password")
        }
    }
}

fun Application.configureAuth() {
    install(Authentication) {
        // VULNERABLE: basic auth over HTTP sends credentials in plaintext [KtorBasicAuthInsecure, CWE-319]
        basic("auth-basic") {
            validate { credentials -> null }
        }
    }
}

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

fun configureJwt() {
    // VULNERABLE: weak hardcoded JWT secret [KtorWeakJwtSecret, CWE-798]
    JWT.require(Algorithm.HMAC256("secret")).build()
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

fun Application.configureCors() {
    install(CORS) {
        // VULNERABLE: wildcard CORS [KtorPermissiveCors, CWE-346]
        anyHost()
    }
}

fun Application.configureSessions() {
    install(Sessions) {
        // VULNERABLE: cookie without encryption or domain restriction [KtorInsecureCookieSession, KtorSessionCookieDomainMissing, CWE-565]
        cookie<UserSession>("SESSION") {
            cookie.path = "/"
        }
    }
}

// VULNERABLE: plaintext session cookie [KtorInsecureCookieSession, CWE-614]
fun Application.configureInsecureSessions() {
    install(Sessions) {
        cookie<UserSession>("PLAIN_SESSION")
    }
}

fun Application.configureHeaders() {
    install(DefaultHeaders) {
        // VULNERABLE: no clickjacking protection header configured [KtorSecurityHeadersMissing, CWE-16]
    }
    routing {
        get("/api/data") { call.respondText("data") }
    }
}

// VULNERABLE: routing without TLS redirect plugin installed [KtorSslRedirectMissing, CWE-319]
fun Application.configureUnsecuredRoutes() {
    routing {
        get("/public") { call.respondText("ok") }
    }
}

fun Application.configureCookies() {
    routing {
        get("/set-cookie") {
            // VULNERABLE: cookie without secure=true [KtorClearTextCookie, CWE-614]
            val cookie = io.ktor.http.Cookie("session", "token-abc")
            call.response.cookies.append(cookie)
        }
    }
}

// ── A03 Injection ─────────────────────────────────────────────────────────────

fun Application.configureDatabase() {
    routing {
        get("/users/{name}") {
            val name = call.parameters["name"]
            // VULNERABLE: SQL via Exposed ORM exec() with interpolation [KtorExposedOrmInjection, CWE-89]
            org.jetbrains.exposed.sql.transactions.transaction {
                org.jetbrains.exposed.sql.transactions.TransactionManager.current()
                    .exec("SELECT * FROM users WHERE name = '$name'")
            }
        }

        get("/users/by-id") {
            // VULNERABLE: route param directly in query [KtorSensitiveRouteParam, CWE-89]
            org.jetbrains.exposed.sql.transactions.transaction {
                org.jetbrains.exposed.sql.transactions.TransactionManager.current()
                    .exec("SELECT * FROM users WHERE id = ${call.parameters["id"]}")
            }
        }

        get("/greet") {
            val name = call.parameters["name"] ?: "World"
            // VULNERABLE: user input in HTML response [KtorXssResponse, CWE-79]
            call.respondText("<h1>Hello $name</h1>", ContentType.Text.Html)
        }

        get("/redirect") {
            val url = call.parameters["url"] ?: "/"
            // VULNERABLE: open redirect [KtorInsecureRedirect, CWE-601]
            call.respondRedirect(url)
        }
    }
}

fun Application.configureExposedInjection() {
    routing {
        get("/users/search") {
            val id = call.parameters["id"]
            // VULNERABLE: exec() with string concatenation [KtorExposedRawSqlConcat, CWE-89]
            org.jetbrains.exposed.sql.transactions.transaction {
                org.jetbrains.exposed.sql.transactions.TransactionManager.current()
                    .exec("SELECT * FROM users WHERE id = " + id)
            }
        }
    }
}

fun purgeAllUsers() {
    // VULNERABLE: deleteAll() wipes entire table [KtorExposedDeleteAll, CWE-285]
    org.jetbrains.exposed.sql.transactions.transaction {
        Users.deleteAll()
    }
}

fun bootstrapSchema() {
    // VULNERABLE: SchemaUtils.create in application boot [KtorExposedSchemaAutoCreate, CWE-284]
    org.jetbrains.exposed.sql.transactions.transaction {
        SchemaUtils.create(Users)
    }
}

// ── A07 Identification and Authentication Failures ────────────────────────────

object DbConfig {
    fun connectToDatabase() {
        // VULNERABLE: hardcoded DB password [KtorHardcodedDatabasePassword, CWE-798]
        Database.connect(
            url = "jdbc:postgresql://localhost/mydb",
            driver = "org.postgresql.Driver",
            user = "admin",
            password = "prodDbPassword123!",
        )
    }

    fun connectInsecure() {
        // VULNERABLE: SSL disabled in JDBC URL [KtorExposedConnectionNotSecure, CWE-319]
        Database.connect(
            url = "jdbc:mysql://localhost/mydb?useSSL=false",
            driver = "com.mysql.cj.jdbc.Driver",
        )
    }
}

fun Application.configureSessionEncryption() {
    install(Sessions) {
        cookie<UserSession>("SECURE_SESSION") {
            // VULNERABLE: hardcoded encryption key [KtorHardcodedSecretKey, CWE-798]
            transform(io.ktor.server.sessions.SessionTransportTransformerEncrypt("hardcoded-key-abc1234", "hardcoded-sign-abc"))
        }
    }
}

fun checkPassword(credentials: UserCredentials) {
    // VULNERABLE: password compared against literal — timing attack [KtorHardcodedPasswordComparison, CWE-798]
    if (credentials.password == "adminPassword123!") {
        println("Access granted")
    }
}

// ── Faza 3 additions ─────────────────────────────────────────────────────────

// VULNERABLE: webSocket without authenticate{} [KtorWebSocketNoAuth, CWE-285]
fun Application.configureWebSocket() {
    routing {
        webSocket("/ws/chat") {
            for (frame in incoming) { outgoing.send(frame) }
        }
    }
}

// VULNERABLE: originalFileName directly in File() [KtorFileUploadTraversal, CWE-22]
fun Application.configureUpload() {
    routing {
        post("/upload") {
            val multipart = call.receiveMultipart()
            multipart.forEachPart { part ->
                if (part is io.ktor.http.content.PartData.FileItem) {
                    val file = File(part.originalFileName!!)
                    file.writeBytes(part.streamProvider().readBytes())
                }
            }
        }
    }
}

// VULNERABLE: install(ForwardedHeaders) unconditionally [KtorForwardedHeaderTrust, CWE-346]
fun Application.configureProxy() {
    install(ForwardedHeaders)
}

// VULNERABLE: exception handler leaks cause.message [KtorStatusPageLeakDetails, CWE-209]
fun Application.configureStatusPages() {
    install(io.ktor.server.plugins.statuspages.StatusPages) {
        exception<Exception> { cause ->
            call.respond(io.ktor.http.HttpStatusCode.InternalServerError, cause.message ?: "error")
        }
    }
}

// VULNERABLE: receiveMultipart() without maxFileSize [KtorMultipartInsecureUpload, CWE-400]
fun Application.configureUnlimitedUpload() {
    routing {
        post("/bulk") {
            val multipart = call.receiveMultipart()
            multipart.forEachPart { it.dispose() }
        }
    }
}

// VULNERABLE: Java serialization content type [KtorInsecureContentNegotiation, CWE-502]
val javaSerialContentType = "application/x-java-serialized-object"

// VULNERABLE: call.receive<Any>() bypasses type safety [KtorRawCallReceive, CWE-20]
fun Application.configureRawReceive() {
    routing {
        post("/data") {
            val body = call.receive<Any>()
            println(body)
        }
    }
}

// VULNERABLE: call.parameters["id"]!! causes 500 on missing param [KtorUnvalidatedQueryParam, CWE-20]
fun Application.configureUnvalidatedParam() {
    routing {
        get("/users/{id}") {
            val id = call.parameters["id"]!!
            call.respondText("User: $id")
        }
    }
}

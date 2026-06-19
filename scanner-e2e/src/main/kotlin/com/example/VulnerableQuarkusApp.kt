package com.example

import javax.ws.rs.BeanParam
import javax.ws.rs.Consumes
import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.QueryParam
import javax.ws.rs.core.Context
import javax.ws.rs.core.NewCookie
import javax.ws.rs.core.Response
import javax.ws.rs.core.SecurityContext
import java.net.URI

// ── A01 Broken Access Control ─────────────────────────────────────────────────

@Path("/admin")
class AdminResource {
    // VULNERABLE: no @RolesAllowed [QuarkusMissingAuth, CWE-285]
    @GET
    @Path("/users")
    fun listUsers(): Response = Response.ok().build()

    // VULNERABLE: @PermitAll on write (DELETE) endpoint [QuarkusPermitAllSensitive, CWE-285]
    @javax.ws.rs.DELETE
    @Path("/transactions")
    @javax.annotation.security.PermitAll
    fun deleteTransactions(): Response = Response.ok().build()

    @POST
    @Path("/shutdown")
    fun emergencyShutdown(): Response {
        // VULNERABLE: allows DoS [QuarkusSystemExit, CWE-400]
        System.exit(1)
        return Response.ok().build()
    }

    // VULNERABLE: exitProcess variant [QuarkusSystemExit, CWE-400]
    @POST
    @Path("/kill")
    fun kill(): Response {
        kotlin.system.exitProcess(0)
        return Response.ok().build()
    }
}

@Path("/api")
class ResourceWithMethodAuth {
    // VULNERABLE: class-level GET accessible before auth rules fire [QuarkusJsonBeforeAuth, CWE-285]
    @GET
    @javax.annotation.security.RolesAllowed("admin")
    fun list(): Response = Response.ok().build()
}

@Path("/redirect")
class RedirectResource {
    @GET
    fun redirect(@QueryParam("to") redirectTo: String): Response {
        // VULNERABLE: open redirect [QuarkusOpenRedirect, CWE-601]
        return Response.seeOther(URI(redirectTo)).build()
    }
}

// VULNERABLE: REST client over HTTP [QuarkusRestClientInsecureUrl, CWE-319]
@io.quarkus.rest.client.reactive.RegisterRestClient(baseUri = "http://payment-service:8080")
interface PaymentClient {
    @GET
    @Path("/payments")
    fun getPayments(): List<String>
}

@io.smallrye.graphql.api.GraphQLApi
// VULNERABLE: no auth on GraphQL API [QuarkusGraphQLNoAuth, CWE-285]
class ProductApi {
    @io.smallrye.graphql.api.Query
    fun products(): List<String> = emptyList()
}

class ReactiveRouteHandler {
    // VULNERABLE: reactive route without auth [QuarkusReactiveRouteNoAuth, CWE-285]
    @io.quarkus.vertx.web.Route(path = "/profile")
    fun profile(rc: io.vertx.ext.web.RoutingContext) {
        rc.response().end("profile")
    }
}

@Path("/login-form")
class FormResource {
    // VULNERABLE: form POST without CSRF token [QuarkusFormCsrfMissing, CWE-352]
    @POST
    @Consumes(javax.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED)
    fun login(@QueryParam("username") u: String, @QueryParam("password") p: String): Response =
        Response.ok().build()
}

@Path("/secure")
class UnsafeContextResource {
    // VULNERABLE: SecurityContext injected but isUserInRole never called [QuarkusUnsafeSecurityContext, CWE-285]
    @GET
    fun sensitive(@Context ctx: SecurityContext): Response {
        // SecurityContext available but no role check performed
        return Response.ok("sensitive data").build()
    }
}

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

// NOTE: Crypto misconfiguration rules are covered by application.properties:
// quarkus.oidc.tls.verification=none → QuarkusOidcAudienceMissing + QuarkusOidcInsecureConfig
// quarkus.grpc.clients.payment.plain-text=true → QuarkusGrpcInsecure
// quarkus.mongodb.connection-string=mongodb://... → QuarkusMongoInsecure
// mp.jwt.verify.secret.value=hardcoded → QuarkusSmallryeJwtInsecure

// ── A03 Injection ─────────────────────────────────────────────────────────────

class UserEntity : io.quarkus.hibernate.orm.panache.PanacheEntity() {
    var name: String = ""
    var role: String = ""
    var password: String = ""
}

class UserRepository {
    fun findByName(name: String) {
        // VULNERABLE: Panache raw query with interpolation [PanacheRawQuery, CWE-89]
        UserEntity.find("name = '$name'")
    }

    fun findByRole(role: String) {
        // VULNERABLE: native query injection [QuarkusNativeQueryInjection, CWE-89]
        val em = javax.persistence.Persistence.createEntityManagerFactory("default").createEntityManager()
        em.createNativeQuery("SELECT * FROM users WHERE role = '$role'").resultList
    }
}

@Path("/users")
class UserResource {
    // VULNERABLE: @PathParam value interpolated into Panache query [QuarkusPathParamInjection, CWE-89]
    @GET
    @Path("/{id}")
    fun getById(@PathParam("id") id: String): Response {
        UserEntity.find("id = '$id'")
        return Response.ok().build()
    }

    // VULNERABLE: password as query param [QuarkusSensitiveQueryParam, CWE-598]
    @POST
    @Path("/login")
    fun login(@QueryParam("password") password: String): Response = Response.ok().build()

    // VULNERABLE: no @Valid on request body [QuarkusMissingBeanValidation, CWE-20]
    @POST
    fun create(user: UserDto): Response = Response.ok().build()
}

data class UserDto(val username: String = "", val password: String = "")

// ── A04 Insecure Design ────────────────────────────────────────────────────────

class UserBeanParam {
    var id: Long = 0
    var isAdmin: Boolean = false
    var password: String = ""
}

@Path("/resources")
class ResourceController {
    // VULNERABLE: mass assignment via @BeanParam [QuarkusMassAssignment, CWE-915]
    @POST
    fun create(@BeanParam entity: UserBeanParam): Response = Response.ok().build()
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

@Path("/session")
class SessionResource {
    @GET
    fun createSession(): Response {
        // VULNERABLE: cookie without secure flag [QuarkusInsecureCookie, CWE-614]
        val cookie = NewCookie("session", "token-value")
        return Response.ok().cookie(cookie).build()
    }
}

class UploadResource {
    // VULNERABLE: insecure file upload [QuarkusInsecureFileUpload, CWE-22]
    @POST
    @Path("/upload")
    fun upload(upload: io.quarkus.rest.runtime.multipart.FileUpload): Response {
        val dest = java.io.File(upload.fileName())
        return Response.ok().build()
    }
}

@Path("/headers")
class HeaderResource {
    @GET
    fun setHeader(@QueryParam("value") userInput: String): Response {
        // VULNERABLE: user input in response header [QuarkusUnsafeHeader, CWE-113]
        return Response.ok().header("X-Custom", userInput).build()
    }
}

// ── A07 Identification and Authentication Failures ────────────────────────────

class AppConfig {
    // VULNERABLE: hardcoded secret in @ConfigProperty default [QuarkusHardcodedConfigSecret, CWE-798]
    @org.eclipse.microprofile.config.inject.ConfigProperty(name = "jwt.secret", defaultValue = "hardcoded-jwt-secret-key")
    lateinit var jwtSecret: String

    // VULNERABLE: hardcoded DB password [QuarkusHardcodedDatasourcePassword, CWE-798]
    @org.eclipse.microprofile.config.inject.ConfigProperty(name = "db.password", defaultValue = "prodPassword!")
    lateinit var dbPassword: String

    // VULNERABLE: password in @ConfigProperty name (leaked in logs/actuator) [QuarkusConfigPasswordLeak, CWE-312]
    @org.eclipse.microprofile.config.inject.ConfigProperty(name = "quarkus.datasource.password")
    lateinit var datasourcePassword: String

    // VULNERABLE: hardcoded property default [QuarkusHardcodedConfigPropertyDefault, CWE-798]
    @org.eclipse.microprofile.config.inject.ConfigProperty(name = "app.api.token", defaultValue = "default-api-token-123")
    lateinit var apiToken: String
}

// NOTE: quarkus.oidc.tls.verification=none in properties → QuarkusOidcInsecureConfig

// ── A08 Software and Data Integrity ──────────────────────────────────────────

class DeserializationService {
    // VULNERABLE: Jsonb deserialization to Object [QuarkusJsonbUnsafeDeserialization, CWE-502]
    fun deserialize(json: String): Any {
        val jsonb = javax.json.bind.JsonbBuilder.create()
        return jsonb.fromJson(json, Object::class.java)
    }
}

@io.quarkus.runtime.annotations.RegisterForReflection
// VULNERABLE: @RegisterForReflection + Serializable + readObject = gadget chain risk [QuarkusReflectionUnsafe, CWE-502]
class SerializableEntity : java.io.Serializable {
    private fun readObject(ois: java.io.ObjectInputStream) {
        ois.defaultReadObject()
    }
}

// ── A09 Security Logging and Monitoring ──────────────────────────────────────

class AuthService {
    private val log = org.jboss.logging.Logger.getLogger(AuthService::class.java)

    fun login(username: String, password: String) {
        // VULNERABLE: password in logs [QuarkusPasswordInLog, CWE-532]
        log.infof("Login: username=%s password=%s", username, password)
    }
}

// VULNERABLE: exception message returned in response [QuarkusExceptionMessageLeak, CWE-209]
@io.quarkus.rest.common.runtime.exceptionmappers.ServerExceptionMapper
fun mapGlobalException(e: Exception): Response =
    Response.serverError().entity(e.message).build()

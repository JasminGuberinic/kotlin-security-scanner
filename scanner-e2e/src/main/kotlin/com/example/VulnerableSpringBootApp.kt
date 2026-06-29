package com.example

import org.springframework.cache.annotation.Cacheable
import org.springframework.context.annotation.Bean
import org.springframework.data.domain.Sort
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

// ── A01 Broken Access Control ─────────────────────────────────────────────────

@RestController
@RequestMapping("/admin")
class AdminController {
    // VULNERABLE: no @PreAuthorize [MissingAuthorization, CWE-285]
    @GetMapping("/users")
    fun listUsers(): List<String> = emptyList()

    @DeleteMapping("/users/{id}")
    fun deleteUser(@PathVariable id: Long) {}
}

// VULNERABLE: debug=true logs auth decisions in prod [SpringSecurityDebugEnabled, CWE-532]
@EnableWebSecurity(debug = true)
class DebugSecurityConfig

class SecurityConfig {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        // VULNERABLE: CSRF disabled [SpringCsrfDisabled, CWE-352]
        http.csrf().disable()
        http.authorizeHttpRequests { auth ->
            // VULNERABLE: permits all [DisabledHttpSecurity, CWE-285]
            auth.anyRequest().permitAll()
            // VULNERABLE: admin path open [PermitAllAdminPath, CWE-285]
            auth.requestMatchers("/admin/users").permitAll()
        }
        // MissingHttpsRedirect: no channel enforcement; SecurityHeadersMissing: no header block
        return http.build()
    }

    @Bean
    fun corsConfig(): org.springframework.web.cors.UrlBasedCorsConfigurationSource {
        val config = org.springframework.web.cors.CorsConfiguration()
        // VULNERABLE: wildcard origin [PermissiveCors, CWE-346]
        config.addAllowedOrigin("*")
        val source = org.springframework.web.cors.UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", config)
        return source
    }

    // VULNERABLE: HTTP method override filter [HttpMethodOverride, CWE-20]
    @Bean
    fun methodFilter() = org.springframework.web.filter.HiddenHttpMethodFilter()
}

@RestController
@RequestMapping("/auth")
class AuthController {
    fun configureRememberMe(http: HttpSecurity) {
        // VULNERABLE: hardcoded remember-me key [InsecureRememberMe, CWE-798]
        http.rememberMe().key("hardcoded-remember-me-key")
    }

    @GetMapping("/redirect")
    fun redirect(@RequestParam returnUrl: String): String {
        // VULNERABLE: open redirect [OpenRedirect, CWE-601]
        return "redirect:$returnUrl"
    }

    @PostMapping("/forward")
    fun forward(
        request: javax.servlet.http.HttpServletRequest,
        response: javax.servlet.http.HttpServletResponse,
        @RequestParam forwardPath: String,
    ) {
        // VULNERABLE: unvalidated forward [UnvalidatedForward, CWE-601]
        request.getRequestDispatcher(forwardPath).forward(request, response)
    }
}

// ── A01 — Async / coroutine security context loss ────────────────────────────

class SecurityContextService {
    @org.springframework.scheduling.annotation.Async
    fun process() {
        // VULNERABLE: async loses security context [AsyncSecurityContextLoss, CWE-362]
        val auth = org.springframework.security.core.context.SecurityContextHolder.getContext().authentication
        println(auth)
    }

    @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
    suspend fun deleteUserCoroutine(id: Long) {
        // VULNERABLE: coroutine loses security context [CoroutineSecurityContextLoss, CWE-362]
    }

    fun leakCsrfToken(csrfToken: org.springframework.security.web.csrf.CsrfToken): org.springframework.ui.ModelMap {
        val model = org.springframework.ui.ModelMap()
        // VULNERABLE: CSRF token in model [CsrfTokenLeak, CWE-352]
        model.addAttribute("_csrf", csrfToken)
        return model
    }
}

// ── A01 — Feign client over plain HTTP ───────────────────────────────────────

@org.springframework.cloud.openfeign.FeignClient(name = "users", url = "http://users-service")
// VULNERABLE: HTTP not HTTPS [FeignClientInsecureUrl, CWE-319]
interface UserServiceClient {
    @GetMapping("/users")
    fun getUsers(): List<String>
}

// ── A02 Cryptographic Failures ────────────────────────────────────────────────

class PasswordService {
    // VULNERABLE: MD5 password hashing [InsecurePasswordEncoder, CWE-916]
    val weakEncoder = org.springframework.security.crypto.password.Md5PasswordEncoder()
    // VULNERABLE: plain-text storage [SpringBootNoOpPasswordEncoder, CWE-916]
    val noopEncoder = NoOpPasswordEncoder.getInstance()
    // VULNERABLE: BCrypt strength too low [WeakBcryptRounds, CWE-916]
    val weakBcrypt = BCryptPasswordEncoder(4)
}

class RedisConfig {
    @Bean
    fun redisConnection() {
        // VULNERABLE: unencrypted Redis [InsecureRedisConnection, CWE-319]
        org.springframework.data.redis.connection.RedisStandaloneConfiguration("redis-host", 6379)
    }
}

// VULNERABLE: hardcoded default JWT secret [SpringBootHardcodedValueDefault, CWE-798]
@org.springframework.beans.factory.annotation.Value("\${jwt.secret:-hardcoded-jwt-secret-for-prod}")
private val jwtSecretValue: String = ""

// ── A03 Injection ─────────────────────────────────────────────────────────────

@RestController
@RequestMapping("/search")
class SearchController {
    @GetMapping
    fun searchJpql(@RequestParam query: String, em: javax.persistence.EntityManager): List<Any> {
        // VULNERABLE: JPQL injection [EntityManagerJpqlInjection, CWE-89]
        return em.createQuery("SELECT u FROM User u WHERE u.name = '$query'").resultList
    }

    @GetMapping("/mongo")
    fun searchMongo(
        @RequestParam fieldName: String,
        @RequestParam value: String,
        mongoTemplate: org.springframework.data.mongodb.core.MongoTemplate,
    ): List<Any> {
        // VULNERABLE: MongoDB injection [SpringDataMongoInjection, CWE-943]
        val criteria = org.springframework.data.mongodb.core.query.Criteria.where(fieldName).`is`(value)
        return mongoTemplate.find(org.springframework.data.mongodb.core.query.Query(criteria), Any::class.java)
    }

    @GetMapping("/sorted")
    fun searchSorted(@RequestParam sortField: String) {
        // VULNERABLE: sort injection [SpringDataSortInjection, CWE-89]
        Sort.by(sortField)
    }
}

fun evaluateExpression(userInput: String): Any? {
    // VULNERABLE: SpEL injection [SpelInjection, CWE-94]
    val parser = org.springframework.expression.spel.standard.SpelExpressionParser()
    return parser.parseExpression(userInput).getValue()
}

class TemplateController {
    fun renderTemplate(templateName: String, ctx: org.thymeleaf.context.Context): String {
        // VULNERABLE: SSTI [ThymeleafSSTI, CWE-94]
        return org.thymeleaf.TemplateEngine().process(templateName, ctx)
    }
}

class ElController {
    fun evalEl(userInput: String) {
        // VULNERABLE: EL injection [ELInjection, CWE-94]
        javax.el.ExpressionFactory.newInstance().createValueExpression(null, userInput, Any::class.java)
    }
}

@RestController
class ResponseController {
    @GetMapping("/header")
    fun setHeader(@RequestParam userInput: String, response: javax.servlet.http.HttpServletResponse) {
        // VULNERABLE: response splitting [ResponseSplitting, CWE-113]
        response.addHeader("X-Custom-Header", userInput)
    }
}

// ── A04 Insecure Design — Mass assignment ─────────────────────────────────────

@javax.persistence.Entity
class UserEntity {
    @javax.persistence.Id
    var id: Long = 0
    var username: String = ""
    var password: String = ""
    var isAdmin: Boolean = false
}

@RestController
class UserController {
    // VULNERABLE: JPA entity as request body [MassAssignment, CWE-915]
    @PostMapping("/users")
    fun createUser(@RequestBody user: UserEntity): UserEntity = user

    // VULNERABLE: Any type as request body [SpringBootRequestBodyAnyType, CWE-20]
    @PostMapping("/update")
    fun updateAny(@RequestBody body: Any): Any = body
}

// ── A05 Security Misconfiguration ────────────────────────────────────────────

class CookieService {
    fun makeCookie() {
        val cookie = javax.servlet.http.Cookie("session", "value123")
        // VULNERABLE: not http-only [SpringBootCookieNotHttpOnly, CWE-1004]
        cookie.isHttpOnly = false
    }
}

class FileUploadController {
    // VULNERABLE: original filename used as path [SpringBootInsecureFileUpload, CWE-22]
    @PostMapping("/upload")
    fun upload(file: org.springframework.web.multipart.MultipartFile) {
        file.transferTo(java.io.File(file.originalFilename!!))
    }
}

@CrossOrigin(allowCredentials = "true")
// VULNERABLE: credentials with wildcard [CrossOriginCredentialsWildcard, CWE-346]
@RestController
class CrossOriginController {
    @GetMapping("/data")
    fun data(): String = "sensitive"
}

// ── A07 Identification and Authentication Failures ────────────────────────────

class DataSourceConfig {
    // VULNERABLE: hardcoded password [HardcodedCredentials, CWE-798]
    val datasourcePassword = "prodPassword123"
}

class JwtService {
    // VULNERABLE: JWT without expiry claim [JwtExpirationMissing, CWE-613]
    fun buildToken(): String = io.jsonwebtoken.Jwts.builder().subject("user").compact()
}

// ── A08 Software Integrity ────────────────────────────────────────────────────

class CacheService {
    // VULNERABLE: sensitive data cached [SpringCacheableSensitive, CWE-524]
    @Cacheable("tokens")
    fun getAccessToken(userId: Long): String = "token-$userId"
}

// ── A09 Security Logging ──────────────────────────────────────────────────────

@org.springframework.web.bind.annotation.ControllerAdvice
class GlobalExceptionHandler {
    // VULNERABLE: exception detail in response body [ExceptionDetailsExposed / SpringBootExceptionBodyLeak, CWE-209]
    @ExceptionHandler
    fun handle(e: Exception) = org.springframework.http.ResponseEntity.badRequest().body(e.message)
}

// ── A10 SSRF ──────────────────────────────────────────────────────────────────

@RestController
class ProxyController {
    // VULNERABLE: RestTemplate with user URL [RestTemplateSsrf, CWE-918]
    @PostMapping("/fetch")
    fun fetch(url: String): String =
        org.springframework.web.client.RestTemplate().getForObject(url, String::class.java) ?: ""

    // VULNERABLE: WebClient with user URL [WebClientSSRF, CWE-918]
    @PostMapping("/webclient")
    fun fetchWebClient(url: String): String =
        org.springframework.web.reactive.function.client.WebClient.create(url)
            .get().retrieve().bodyToMono(String::class.java).block() ?: ""
}

// ── Batch: security header / session hardening ────────────────────────────────

// VULNERABLE: X-Frame-Options disabled [SpringFrameOptionsDisabled, CWE-1021]
fun configFrameOptions(http: Any) {
    http.headers { frameOptions { disable() } }
}

// VULNERABLE: X-Content-Type-Options disabled [SpringContentTypeOptionsDisabled, CWE-693]
fun configContentType(http: Any) {
    http.headers { contentTypeOptions { disable() } }
}

// VULNERABLE: session fixation protection disabled [SpringSessionFixationNone, CWE-384]
fun configSessionFixation(http: Any) {
    http.sessionManagement { sessionFixation { none() } }
}

// VULNERABLE: CSRF excluded for matched paths [SpringCsrfIgnoringMatchers, CWE-352]
fun configCsrfIgnoring(http: Any) {
    http.csrf { it.ignoringRequestMatchers(apiPathPattern) }
}

private const val apiPathPattern = "/api/everything"

// ── Batch: WebFlux (reactive) ─────────────────────────────────────────────────

// VULNERABLE: ThreadLocal SecurityContextHolder in reactive code [ReactiveSecurityContextHolder, CWE-863]
fun reactiveMe(): reactor.core.publisher.Mono<String> {
    val auth = org.springframework.security.core.context.SecurityContextHolder.getContext().authentication
    return reactor.core.publisher.Mono.just(auth.name)
}

// VULNERABLE: reactive authorizeExchange permits everything [ReactivePermitAllExchange, CWE-285]
fun reactiveSecurity(http: Any) {
    http.authorizeExchange { it.anyExchange().permitAll() }
}

// VULNERABLE: blocking call inside a reactive method [WebFluxBlockingCall, CWE-400]
fun reactiveHandler(repo: Any, id: Long): reactor.core.publisher.Mono<String> {
    val user = repo.findById(id).block()
    return reactor.core.publisher.Mono.just(user.toString())
}

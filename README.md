# WebAuth — API REST de Autenticación y JWT

Microservicio independiente extraído del monolito modular `com.udea.Backend` (Spring Modulith).  
Se encarga exclusivamente de la **autenticación de usuarios** y de la **emisión/validación de tokens Bearer JWT**.  
Paquete raíz: `com.udea.webauth`

## Contexto en la arquitectura

Este servicio corresponde al módulo `Usuarios / Plataforma.Security` del monolito original.  
Los demás servicios del ecosistema (**Masters** y **Business**) son **Resource Servers**: validan el JWT emitido por WebAuth de forma local (misma clave secreta compartida), sin llamadas en tiempo real a este servicio.

```
Cliente → POST /api/v1/auth/login → WebAuth (emite JWT)
Cliente → cualquier otro endpoint  → Masters / Business (validan JWT localmente)
```

## Tech Stack

| Capa               | Tecnología                                                |
|--------------------|-----------------------------------------------------------|
| Lenguaje           | Java 21                                                   |
| Framework          | Spring Boot 4.1.1 (WebMVC)                                |
| Seguridad          | Spring Security + JJWT 0.12.5 (Stateless Bearer JWT HS256)|
| Base de datos      | PostgreSQL (Supabase) — Spring Data JPA / Hibernate       |
| Base datos pruebas | H2 in-memory (`MODE=PostgreSQL`)                          |
| Validación         | Jakarta Bean Validation                                   |
| Documentación API  | SpringDoc OpenAPI 2.6.0 (Swagger UI en `/swagger-ui.html`)|
| Boilerplate        | Lombok                                                    |
| Build              | Maven (wrapper: `mvnw` / `mvnw.cmd`)                      |
| Calidad & Cobertura| JaCoCo 0.8.11 + SonarCloud                               |
| Contenedores       | Docker multi-stage (eclipse-temurin:21)                   |
| Tests              | JUnit 5 + Mockito + Spring Boot Test                      |

## Estructura del proyecto

```
src/main/java/com/udea/webauth/
├── WebAuthApplication.java          # @SpringBootApplication — punto de entrada
├── HealthController.java            # GET /api/v1/health
│
├── config/
│   └── SwaggerConfig.java           # Configuración OpenAPI con soporte Bearer JWT
│
├── controllers/
│   ├── AuthController.java          # POST /api/v1/auth/login · GET /api/v1/auth/validate
│   └── DTOs/
│       ├── LoginRequest.java        # { email, password }
│       ├── AuthResponse.java        # { token, tipo, idUsuario, email, roles }
│       └── ValidateTokenResponse.java # { valid, idUsuario, email, roles }
│
├── entities/
│   ├── UsuarioAuth.java             # Entidad ligera: id, email, passwordHash, activo
│   └── RolAuth.java                 # Entidad ligera: id, nombre (TipoRol)
│
├── repositories/
│   └── UsuarioAuthRepository.java   # findByEmail
│
├── security/
│   ├── IJwtService.java             # Contrato: generateToken, extractUserId, isTokenValid
│   ├── JwtService.java              # Implementación HS256 · JJWT 0.12.5
│   ├── JwtAuthenticationFilter.java # OncePerRequestFilter — valida Bearer en cada petición
│   └── SecurityConfig.java          # SecurityFilterChain STATELESS · rutas públicas/privadas
│
└── services/
    ├── IAuthService.java            # Contrato: login, validateToken
    └── AuthService.java             # BCrypt verify → JwtService.generateToken
```

## API Endpoints

| Método | Ruta                    | Seguridad        | Descripción                                                  |
|--------|-------------------------|------------------|--------------------------------------------------------------|
| `GET`  | `/api/v1/health`        | Público          | Health check de la API                                       |
| `POST` | `/api/v1/auth/login`    | Público          | Autentica usuario y retorna JWT con claims de identidad y roles |
| `GET`  | `/api/v1/auth/validate` | Bearer JWT       | Valida el estado del token y retorna los claims decodificados |
| `GET`  | `/swagger-ui.html`      | Público          | Documentación interactiva Swagger UI                         |
| `GET`  | `/v3/api-docs`          | Público          | Especificación OpenAPI v3 en JSON                            |

### Ejemplo — Login

**Request**
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "propietario@udea.edu.co",
  "password": "secreto123"
}
```

**Response 200 OK**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "tipo": "Bearer",
  "idUsuario": 42,
  "email": "propietario@udea.edu.co",
  "roles": ["PROPIETARIO"]
}
```

**Response 401 Unauthorized**
```json
{ "error": "Credenciales inválidas o usuario inactivo." }
```

### Ejemplo — Validate Token

**Request**
```http
GET /api/v1/auth/validate
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

**Response 200 OK**
```json
{
  "valid": true,
  "idUsuario": 42,
  "email": "propietario@udea.edu.co",
  "roles": ["PROPIETARIO"]
}
```

## Configuración y variables de entorno

Copia `.env.example` como `.env` en la raíz del proyecto y completa los valores:

```bash
cp .env.example .env
```

| Variable            | Descripción                              | Valor por defecto / Ejemplo                             |
|---------------------|------------------------------------------|---------------------------------------------------------|
| `DB_HOST`           | Host de PostgreSQL (Supabase)            | `aws-0-...pooler.supabase.com`                          |
| `DB_PORT`           | Puerto de base de datos                  | `5432`                                                  |
| `DB_NAME`           | Nombre de la base de datos               | `postgres`                                              |
| `DB_USERNAME`       | Usuario de base de datos                 | `postgres.xxx`                                          |
| `DB_PASSWORD`       | Contraseña de base de datos              | `*****`                                                 |
| `DB_SSLMODE`        | Modo SSL                                 | `require`                                               |
| `JPA_DDL_AUTO`      | Estrategia DDL de Hibernate              | `update`                                                |
| `JWT_SECRET`        | Clave secreta Base64 (mín. 256 bits)     | `*****`                                                 |
| `JWT_EXPIRATION_MS` | Tiempo de vida del JWT en ms             | `86400000` (24 horas)                                   |
| `PORT`              | Puerto HTTP del servidor                 | `8081`                                                  |

> **⚠️ IMPORTANTE**: Jamás commitear secretos en texto plano. En producción (Render, CI) las variables se inyectan en el entorno.  
> La clave `JWT_SECRET` debe ser **idéntica** en todos los servicios del ecosistema para que la validación local funcione.

## Comandos de desarrollo

```bash
# Compilar sin tests
./mvnw clean compile          # Linux / macOS
mvnw.cmd clean compile        # Windows

# Ejecutar la aplicación (puerto 8081 por defecto)
./mvnw spring-boot:run
mvnw.cmd spring-boot:run      # Windows

# Empaquetar JAR (sin tests)
./mvnw clean package -DskipTests

# Ejecutar todos los tests (con reporte JaCoCo)
./mvnw test
mvnw.cmd test                 # Windows

# Docker build & run
docker build -t webauth .
docker run -p 8081:8081 --env-file .env webauth
```

## Testing

- **JUnit 5** + **Mockito** (`@ExtendWith(MockitoExtension.class)`)
- **H2 en memoria** configurado en `src/test/resources/application.properties` con modo PostgreSQL (`create-drop`), garantizando tests herméticos sin dependencia de la base de datos de desarrollo.
- Clases de test ubicadas en `src/test/java/com/udea/webauth/` replicando la jerarquía de paquetes de producción.
- Convenciones de nombres: sufijo `Test` (ej. `AuthServiceTest`, `AuthControllerTest`); métodos en camelCase descriptivo sin prefijo `test` (ej. `loginExitoso`, `debeRetornar401CuandoPasswordIncorrecto`).

## Seguridad — Modelo JWT

| Claim   | Valor                                      |
|---------|--------------------------------------------|
| `sub`   | ID del usuario (entero como String)        |
| `email` | Correo electrónico del usuario             |
| `roles` | Lista de roles (ej. `["PROPIETARIO"]`)     |
| `iat`   | Fecha de emisión (Unix timestamp)          |
| `exp`   | Fecha de expiración (`iat + JWT_EXPIRATION_MS`) |

Algoritmo de firma: **HS256**. La clave se carga desde `JWT_SECRET` (Base64-encoded, mínimo 256 bits).

## Convenciones de código

- **Paquetes**: camelCase (`config`, `controllers`, `entities`, `repositories`, `security`, `services`).
- **Clases**: PascalCase. Interfaces de servicio con prefijo `I` (`IAuthService`, `IJwtService`).
- **Métodos y variables**: camelCase. Constantes: `UPPER_SNAKE_CASE`.
- **Idioma**: español para nombres de dominio, Javadoc y mensajes de error.
- Endpoints documentados con `@Operation`, `@ApiResponse` y `@Tag` (SpringDoc/OpenAPI).

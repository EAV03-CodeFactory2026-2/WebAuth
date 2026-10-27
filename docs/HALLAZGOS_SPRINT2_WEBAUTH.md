# Hallazgos de calidad — Sprint 2 — WebAuth

## 1. Resumen de la verificación

| Dato | Valor |
|---|---|
| Microservicio | WebAuth |
| Sprint | 2 |
| Tipo de verificación | Verificación final del Sprint 2 |
| Fecha de verificación | 2026-10-27 |
| Rama y commit verificados | main @ 373dc01 |
| Línea base de comparación | 1b56e51 (merge del PR #4) |
| Tests ejecutados | 77 |
| Fallos | 0 |
| Cobertura de líneas | 98,92 % (183/185) |
| Cobertura de ramas | 100 % (35/35) |
| Cobertura en SonarCloud | 100,0 % |
| Complejidad ciclomática del proyecto | 64 (JaCoCo), 48 (JaCoCo con exclusiones de Sonar), 45 (SonarCloud) |
| Complejidad máxima por clase | 18 (AuthService) |

## 2. Resumen por severidad

| Severidad | Vigentes | Corregidos | No vigentes | Cerrados por decisión | Total |
|---|---|---|---|---|---|
| Alta | 0 | 2 | 0 | 0 | 2 |
| Media | 1 | 8 | 0 | 0 | 9 |
| Baja | 0 | 8 | 0 | 2 | 10 |
| Por confirmar | 0 | 0 | 0 | 0 | 0 |
| Total | 1 | 18 | 0 | 2 | 21 |

## 3. Hallazgos

| ID | ID PR | Clase y método | Descripción | Impacto | Severidad | HU / CP | Estado | Recomendación |
|---|---|---|---|---|---|---|---|---|
| H-01 | H1 | AuthService.login (L38-40) | Si la contraseña almacenada no empieza por `$2a$`, se compara en texto plano con `String.equals`, que no es de tiempo constante. Los hashes BCrypt `$2b$` y `$2y$` se tratan como texto plano y el login falla siempre. | Acepta contraseñas sin cifrar y expone la comparación a ataques de temporización. Usuarios con hashes `$2b$`/`$2y$` no pueden autenticarse. | Alta | HU-0002 | Corregido en 1a556ef (AuthService L40) | Verificar en la base de datos que no queden contraseñas sin hash: esas cuentas ya no pueden iniciar sesión. |
| H-02 | H11 | JwtAuthenticationFilter.doFilterInternal (L47-50) | Las authorities se construyen con todos los roles del claim `roles`; el claim `rolActivo` no se usa en la autorización. | `cambiar-rol` no tiene efecto en la autorización: un usuario que opera como Cliente conserva los permisos de Propietario. | Alta | HU-0002 | Corregido en f764f2b (JwtAuthenticationFilter L53-60) | Ninguna acción requerida. |
| H-03 | H2 | AuthService.cambiarRol (L54), AuthService.validateToken (L74) | `Integer.valueOf` sobre el `sub` del token lanza `NumberFormatException` cuando no es numérico. El refactor corrigió el caso `sub` null en `cambiarRol`; el caso no numérico persiste. | En `cambiar-rol` responde 401 con mensaje técnico ("For input string"). En `/validate` la excepción no se controla y termina en 500. | Media | HU-0002 | Corregido en a910fd4 (AuthService L52, L67) | Ninguna acción requerida. Residual en la sección 6. |
| H-04 | H3 | AuthService.validateToken (L73-79) | Un token firmado sin `sub` produce `valid=true` con `userId=null`. | Sesión considerada válida sin identidad asociada. | Media | HU-0002 | Corregido en 4d602ba (AuthService L67) | Ninguna acción requerida. |
| H-05 | H7 | JwtService.generateToken (L37), JwtService.extractAllClaims (L73) | La clave se deriva en cada llamada; la longitud mínima de 256 bits solo se valida al firmar o verificar, no al arrancar. | Con un secreto débil la aplicación arranca, el primer login responde 500 y todos los tokens se rechazan. | Media | HU-0002 | Corregido en 5d18b49 (JwtService L27) | Ninguna acción requerida. |
| H-06 | H8 | JwtService.isTokenValid (L66-67) | `catch (Exception e)` devuelve `false` sin registrar la causa. | Errores de configuración (clave débil, secreto no Base64) son indistinguibles de un token inválido y no dejan traza. | Media | HU-0002 | Corregido en 225d2c6 (JwtService L71-72) | Ninguna acción requerida. |
| H-07 | H12 | SecurityConfig.securityFilterChain (L24-32) | No se configura `authenticationEntryPoint`; Spring Security usa `Http403ForbiddenEntryPoint`. Verificado: sin token, con token inválido o expirado, una ruta protegida responde 403 sin cuerpo y sin `WWW-Authenticate`. | Contradice el 401 esperado por la HU para peticiones no autenticadas. | Media | HU-0002 | Corregido en 8341858 (config/SecurityConfig L50, L57-65) | Ninguna acción requerida. |
| H-08 | H13 | JwtAuthenticationFilter.doFilterInternal (L62) | `catch (Exception ignored)` descarta cualquier excepción, incluida una `NullPointerException` con roles null. | Fallos reales se presentan como peticiones anónimas, sin traza. | Media | HU-0002 | Corregido en 7aac2e7 (JwtAuthenticationFilter L52, L75-76) | Ninguna acción requerida. |
| H-09 | H16 | SecurityConfig.securityFilterChain (L27-29) | Todas las rutas expuestas por el módulo (`/api/v1/health`, `/api/v1/auth/**`, Swagger) son `permitAll`; el filtro JWT no protege ningún endpoint. | La autenticación por Bearer no tiene efecto en el módulo; `cambiar-rol` depende solo de la validación del servicio. El endpoint `/api/v1/usuarios/perfil` no existe. | Media | HU-0002 | Corregido en 3d69318 (config/SecurityConfig L45-48) | Ninguna acción requerida. `/api/v1/usuarios/perfil` sigue sin existir; al crearlo queda protegido por `anyRequest().authenticated()`. |
| H-10 | H18 | AuthController.error (L81) | No hay `@RestControllerAdvice`; las excepciones fuera de las tres controladas se relanzan. | Errores no previstos terminan en un 500 genérico con formato distinto al contrato `{"error": ...}`. | Media | HU-0002 | Corregido en f632c3d (AuthController L65-81) | Ninguna acción requerida sobre el formato. La corrección introdujo H-21. |
| H-11 | H4 | AuthService.extraerTokenValido (L130), JwtAuthenticationFilter.doFilterInternal (L35) | El servicio acepta tokens con o sin prefijo `Bearer ` y, tras el refactor, `StringUtils.delete` elimina la cadena en cualquier posición. El filtro exige el prefijo. | Contrato de entrada inconsistente entre la capa web y el servicio. | Baja | HU-0002 | Corregido en 03fcaf4 (AuthService L127-129) | Ninguna acción requerida. Filtro y servicio aplican la misma regla; la extracción sigue duplicada (sección 6). |
| H-12 | H5 | AuthService.login (L37) | NPE al comparar en texto plano con contraseña almacenada o enviada null. El refactor usa `Objects.requireNonNullElse` y `guardada.equals(...)`, que no falla con null. | Corregido. El residual de la ruta BCrypt (`matches(null, hash)` lanzaba `IllegalArgumentException`) quedó resuelto al normalizar también la contraseña enviada. | Baja | HU-0002 | Corregido en el refactor (583a04c); residual corregido en a750d96 (AuthService L37) | Ninguna acción requerida. |
| H-13 | H9 | JwtService.isTokenValid (L65) | `isTokenExpired` era código muerto porque JJWT rechaza el token expirado antes. El refactor eliminó el método. | Corregido. La comparación redundante `getExpiration().after(new Date())` también se eliminó. | Baja | HU-0002 | Corregido en el refactor (583a04c); redundancia eliminada en da8b0c2 (JwtService L67-70) | Ninguna acción requerida. |
| H-14 | H10 | JwtService.generateToken (L31) | `String.valueOf(usuarioId)` genera `sub="null"` cuando el id es null; encadena con H-03 al convertirlo a entero. | Token emitido con identidad inválida. | Baja | HU-0002 | Corregido en f3e7e35 (JwtService L35) | Ninguna acción requerida. |
| H-15 | H14 | JwtAuthenticationFilter.doFilterInternal (L35) | `startsWith("Bearer ")` distingue mayúsculas; RFC 6750 define el esquema como insensible. | Clientes que envían `bearer` quedan sin autenticar. | Baja | HU-0002 | Corregido en 71f9974 (JwtAuthenticationFilter L40, AuthService L128) | Ninguna acción requerida. |
| H-16 | H15 | JwtAuthenticationFilter.doFilterInternal (L49) | `toUpperCase()` sin `Locale`. | Resultado dependiente de la configuración regional (p. ej. turco); code smell en Sonar. | Baja | HU-0002 | Corregido en d05b979 (JwtAuthenticationFilter L62) | Ninguna acción requerida. |
| H-17 | H17 | AuthController.login (L44), AuthController.cambiarRol (L65) | Los 400 de `@Valid` los resuelve `DefaultHandlerExceptionResolver` sin cuerpo propio. | Los mensajes de validación ("El rol no puede estar vacío.") no llegan al cliente y el formato difiere de `{"error": ...}`. | Baja | HU-0002 | Corregido en b7d4b31 (AuthController L68-72) | Ninguna acción requerida. |
| H-18 | H6 | AuthService.resolverRolActivo (L113), AuthController.error (L77-78) | Un usuario autenticado sin roles recibe `RolNoAsignadoException`, que se traduce a 403. | El equipo confirmó que 403 es la respuesta esperada. | Baja | HU-0002 | Cerrado por decisión (2026-10-25) | Ninguna acción requerida. |
| H-19 | H19 | AuthController.validateToken (L94-95), AuthService.validateToken (L69-70) | `/validate` responde 200 con `valid:false` cuando el token es inválido o no se envía. Coincide con la documentación Swagger. | Discrepancia con el contrato definido por el equipo: 401 con `valid:false`. | Baja | HU-0002 | Corregido en bd21395 (AuthController L94-96) | Ninguna acción requerida. |
| H-20 | H20 | AuthController.error (L79-80) | CP-11 espera 400 para credenciales inválidas; el código y Swagger responden 401. | Caso de prueba desalineado con la implementación. | Baja | HU-0002 / CP-11 | Cerrado por decisión (CP ajustado) | Confirmar el ID del caso de prueba (sección 6). |
| H-21 | — | AuthController.error (L65-81) | El `@ExceptionHandler(Exception.class)` local también captura las excepciones de Spring MVC previas al servicio y las responde con 500 sin registrar la causa. Verificado en `/login`: JSON mal formado, cuerpo vacío o `Content-Type: text/plain` devuelven 500 `{"error":"Error interno del servidor."}`; en 1b56e51 respondían 400 y 415. | Payloads con formato inválido reciben 500 en lugar de 400, contrario al estándar del proyecto. Los errores reales no dejan traza. | Media | HU-0002 | Vigente (introducido en f632c3d, ampliado en b7d4b31) | Responder 400 ante `HttpMessageNotReadableException`, conservar el estado de las excepciones de Spring MVC (`ErrorResponse.getStatusCode()`) y registrar la causa en la rama 500. |

Las líneas de "Clase y método" corresponden a 1b56e51 (H-21: a 373dc01); las del estado corresponden a 373dc01.

## 4. Pendientes de definir con el PO

No aplica. H-18, H-19 y H-20 se definieron con el equipo el 2026-10-25.

## 5. Complejidad ciclomática

| Métrica | Antes (1b56e51) | Después (HEAD) |
|---|---|---|
| Complejidad del proyecto (JaCoCo) | 49 | 64 |
| Complejidad del proyecto con exclusiones de Sonar del `pom.xml` (JaCoCo) | No aplica (sin exclusiones) | 48 |
| Complejidad del proyecto en SonarCloud | 46 | 45 |
| Complejidad máxima por clase | 15 (AuthService) | 18 (AuthService) |

| Clase | Antes (1b56e51) | Después (HEAD) |
|---|---|---|
| AuthService | 15 | 18 |
| SecurityConfig | 4 | 12 |
| JwtService | 8 | 9 |
| AuthController | 8 | 9 |
| JwtAuthenticationFilter | 6 | 8 |

HEAD corresponde a 373dc01. El valor de SonarCloud de 1b56e51 se toma del análisis de 714059d, que tiene el mismo código (solo difiere `.gitignore`); el de HEAD, del análisis de 373dc01 en main.

Nota: el pipeline evalúa complexity < 50. Falta confirmar con el profesor si el límite aplica al proyecto o a la clase.

- Criterio por proyecto: se cumple con el valor oficial de SonarCloud (45 < 50). Sin las exclusiones de Sonar no se cumpliría (64 en JaCoCo).
- Criterio por clase: se cumple (máximo 18).
- La complejidad de SonarCloud bajó de 58 (bd21395) a 45 (373dc01) porque 373dc01 movió `SecurityConfig` al paquete `config` y agregó `sonar.exclusions` (`**/config/**`, `**/entities/**`, `**/*Application.java`). El código de esas clases no cambió.

Valores calculados con JaCoCo 0.8.11 (suma de `COMPLEXITY_MISSED` y `COMPLEXITY_COVERED` de `jacoco.csv`). SonarCloud calcula la complejidad con su propio analizador y puede reportar valores distintos.

## 6. Notas

- H-01 a H-17 y H-19 se corrigieron en `src/main` con un commit por hallazgo el 2026-10-25 (el de H-06 aparece como "H06"). La verificación final no modificó código de producción.
- Tests agregados o ajustados en la verificación final: ninguno. La cobertura de líneas (98,92 %) supera el 85 % y los 77 tests pasan sin cambios sobre 373dc01.
- Tests modificados por arquitectura desde 1b56e51: no se agregó `@Disabled` ni se debilitaron aserciones. En `AuthServiceTest` (25 a 27 tests) se eliminó `loginFallaConContrasenaEnTextoPlanoQueNoCoincide`, porque la ruta de texto plano ya no existe, y los tests que aceptaban texto plano, tokens sin `Bearer` o `sub` nulo se invirtieron para exigir el rechazo (H-01, H-03, H-04, H-11). En `AuthControllerTest`, `JwtAuthenticationFilterTest` y `JwtServiceTest` los cambios reflejan H-02, H-05, H-08, H-10, H-14, H-15, H-17 y H-19. `SecurityConfigTest` es nuevo (3 tests).
- Código nuevo sin prueba explícita: las reglas de `securityFilterChain` (config/SecurityConfig L44-52) solo se ejecutan al cargar el contexto en `WebAuthApplicationTests`; ningún test comprueba que `cambiar-rol` exija autenticación ni que las rutas públicas sigan abiertas. Tampoco hay test para el caso de H-21.
- H-18, H-19 y H-20 se reclasificaron de "Por confirmar" a Baja al definirse con el equipo.
- H-20: en el PDF de casos de prueba, CP-11 es "Registro exitoso de un Proveedor". El camino de excepción de login con credenciales inválidas parece pertenecer al CP anterior. El equipo debe confirmar el ID.
- La nota anterior sobre `AuthService.login` con usuario inexistente ya no aplica: desde 1a556ef la comparación siempre pasa por `BCryptPasswordEncoder.matches`, que devuelve `false` con hash vacío, y la respuesta es 401 "Credenciales inválidas.".
- Observación: con un correo inexistente, `login` (AuthService L36-40) no calcula BCrypt, responde más rápido que con un correo existente y registra el aviso "Empty encoded password". La diferencia de tiempo permite enumerar correos registrados.
- Observación (residual de H-03): un `sub` numérico fuera del rango de `Integer` (p. ej. `99999999999`) pasa el filtro `\d+` y `Integer.valueOf` lanza `NumberFormatException`; `cambiar-rol` y `/validate` responden 401 con el mensaje técnico. Requiere un token firmado con la clave del servicio, que solo emite identificadores `Integer`.
- Observación (H-11): la extracción del token está duplicada en `JwtAuthenticationFilter` (L40-45) y `AuthService.extraerTokenValido` (L126-131), con la misma regla.
- Observación: CORS (config/SecurityConfig L36, L75-79) usa por defecto los patrones `https://*.vercel.app` y `http://localhost:*` con `allowCredentials(true)`; `.env.example` repite esos valores. Cualquier aplicación publicada en `vercel.app` puede invocar la API desde el navegador y leer las respuestas. El impacto actual es bajo porque la API es stateless y no usa cookies. 0b6eec4 había configurado orígenes exactos sin comodines; d701f92 lo reemplazó.
- Observación: `sonar.exclusions` excluye `config/` de todo el análisis de SonarCloud, no solo de cobertura y complejidad; `SecurityConfig` queda fuera de las reglas de bugs, vulnerabilidades y security hotspots.
- Observación: el `README.md` sigue mencionando Supabase (L24 y L160, con el host de ejemplo `aws-0-...pooler.supabase.com`). `.env.example` no lo menciona.
- La rama remota `revert-6-feature/correccion-hallazgos` pertenece al historial anterior al force push y no está integrada en main. main no contiene commits de revert desde 1b56e51.
- Migración de base de datos: la base se migró de Supabase a PostgreSQL en Google Cloud Compute Engine. Los tests usan H2 en memoria (`src/test/resources/application.properties`) y no dependen de la base real. `application.properties` usa `sslmode=require` por defecto y `.env.example` usa `disable` para desarrollo local; el uso de SSL en el PostgreSQL de GCE queda como verificación del equipo.

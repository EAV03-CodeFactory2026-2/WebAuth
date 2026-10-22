# Hallazgos de calidad — Sprint 2 — WebAuth

## 1. Resumen de la verificación

| Dato | Valor |
|---|---|
| Microservicio | WebAuth |
| Sprint | 2 |
| Fecha de verificación | 2026-10-22 |
| Rama y commit verificados | main @ 583a04c |
| Tests ejecutados | 70 |
| Fallos | 0 |
| Cobertura de líneas | 98,68 % (149/151) |
| Cobertura de ramas | 100 % (30/30) |
| Complejidad ciclomática del proyecto | 49 |
| Complejidad máxima por clase | 15 (AuthService) |

## 2. Resumen por severidad

| Severidad | Vigentes | Corregidos | No vigentes | Total |
|---|---|---|---|---|
| Alta | 2 | 0 | 0 | 2 |
| Media | 8 | 0 | 0 | 8 |
| Baja | 5 | 2 | 0 | 7 |
| Por confirmar | 3 | 0 | 0 | 3 |
| Total | 18 | 2 | 0 | 20 |

## 3. Hallazgos

| ID | ID PR | Clase y método | Descripción | Impacto | Severidad | HU / CP | Estado | Recomendación |
|---|---|---|---|---|---|---|---|---|
| H-01 | H1 | AuthService.login (L38-40) | Si la contraseña almacenada no empieza por `$2a$`, se compara en texto plano con `String.equals`, que no es de tiempo constante. Los hashes BCrypt `$2b$` y `$2y$` se tratan como texto plano y el login falla siempre. | Acepta contraseñas sin cifrar y expone la comparación a ataques de temporización. Usuarios con hashes `$2b$`/`$2y$` no pueden autenticarse. | Alta | HU-0002 | Vigente | Delegar siempre en `PasswordEncoder.matches` (o `DelegatingPasswordEncoder`) y migrar las contraseñas en texto plano a BCrypt. |
| H-02 | H11 | JwtAuthenticationFilter.doFilterInternal (L47-50) | Las authorities se construyen con todos los roles del claim `roles`; el claim `rolActivo` no se usa en la autorización. | `cambiar-rol` no tiene efecto en la autorización: un usuario que opera como Cliente conserva los permisos de Propietario. | Alta | HU-0002 | Vigente | Construir las authorities a partir de `rolActivo`, o validarlo explícitamente en las reglas de autorización. |
| H-03 | H2 | AuthService.cambiarRol (L54), AuthService.validateToken (L74) | `Integer.valueOf` sobre el `sub` del token lanza `NumberFormatException` cuando no es numérico. El refactor corrigió el caso `sub` null en `cambiarRol`; el caso no numérico persiste. | En `cambiar-rol` responde 401 con mensaje técnico ("For input string"). En `/validate` la excepción no se controla y termina en 500. | Media | HU-0002 | Vigente | Validar que el `sub` sea numérico y mapear el error a `MSG_TOKEN_INVALIDO` / `valid=false`. |
| H-04 | H3 | AuthService.validateToken (L73-79) | Un token firmado sin `sub` produce `valid=true` con `userId=null`. | Sesión considerada válida sin identidad asociada. | Media | HU-0002 | Vigente | Responder `valid=false` cuando el token no tenga `sub`. |
| H-05 | H7 | JwtService.generateToken (L37), JwtService.extractAllClaims (L73) | La clave se deriva en cada llamada; la longitud mínima de 256 bits solo se valida al firmar o verificar, no al arrancar. | Con un secreto débil la aplicación arranca, el primer login responde 500 y todos los tokens se rechazan. | Media | HU-0002 | Vigente | Construir la `SecretKey` una vez en el constructor para fallar al arrancar y evitar recalcularla en cada petición. |
| H-06 | H8 | JwtService.isTokenValid (L66-67) | `catch (Exception e)` devuelve `false` sin registrar la causa. | Errores de configuración (clave débil, secreto no Base64) son indistinguibles de un token inválido y no dejan traza. | Media | HU-0002 | Vigente | Capturar `JwtException` e `IllegalArgumentException` y registrar la causa con nivel adecuado. |
| H-07 | H12 | SecurityConfig.securityFilterChain (L24-32) | No se configura `authenticationEntryPoint`; Spring Security usa `Http403ForbiddenEntryPoint`. Verificado: sin token, con token inválido o expirado, una ruta protegida responde 403 sin cuerpo y sin `WWW-Authenticate`. | Contradice el 401 esperado por la HU para peticiones no autenticadas. | Media | HU-0002 | Vigente | Configurar `exceptionHandling` con un entry point que responda 401 y cuerpo `{"error": ...}`. |
| H-08 | H13 | JwtAuthenticationFilter.doFilterInternal (L62) | `catch (Exception ignored)` descarta cualquier excepción, incluida una `NullPointerException` con roles null. | Fallos reales se presentan como peticiones anónimas, sin traza. | Media | HU-0002 | Vigente | Capturar solo excepciones de JWT y registrar las inesperadas. |
| H-09 | H16 | SecurityConfig.securityFilterChain (L27-29) | Todas las rutas expuestas por el módulo (`/api/v1/health`, `/api/v1/auth/**`, Swagger) son `permitAll`; el filtro JWT no protege ningún endpoint. | La autenticación por Bearer no tiene efecto en el módulo; `cambiar-rol` depende solo de la validación del servicio. El endpoint `/api/v1/usuarios/perfil` no existe. | Media | HU-0002 | Vigente | Definir qué endpoints requieren autenticación (perfil, gestión de usuarios) y restringirlos. |
| H-10 | H18 | AuthController.error (L81) | No hay `@RestControllerAdvice`; las excepciones fuera de las tres controladas se relanzan. | Errores no previstos terminan en un 500 genérico con formato distinto al contrato `{"error": ...}`. | Media | HU-0002 | Vigente | Agregar un manejador global con formato de error uniforme. |
| H-11 | H4 | AuthService.extraerTokenValido (L130), JwtAuthenticationFilter.doFilterInternal (L35) | El servicio acepta tokens con o sin prefijo `Bearer ` y, tras el refactor, `StringUtils.delete` elimina la cadena en cualquier posición. El filtro exige el prefijo. | Contrato de entrada inconsistente entre la capa web y el servicio. | Baja | HU-0002 | Vigente | Centralizar la extracción del token en un único componente que exija el prefijo. |
| H-12 | H5 | AuthService.login (L37) | NPE al comparar en texto plano con contraseña almacenada o enviada null. El refactor usa `Objects.requireNonNullElse` y `guardada.equals(...)`, que no falla con null. | Corregido. Residual: en la ruta BCrypt, `matches(null, hash)` lanza `IllegalArgumentException` técnica; lo evita `@NotBlank`. | Baja | HU-0002 | Corregido | Mantener `@NotBlank` en `LoginRequest`; validar también en el servicio si se reutiliza fuera del controller. |
| H-13 | H9 | JwtService.isTokenValid (L65) | `isTokenExpired` era código muerto porque JJWT rechaza el token expirado antes. El refactor eliminó el método. | Corregido. La comparación `getExpiration().after(new Date())` sigue siendo redundante, pero no genera ramas. | Baja | HU-0002 | Corregido | Ninguna acción requerida. |
| H-14 | H10 | JwtService.generateToken (L31) | `String.valueOf(usuarioId)` genera `sub="null"` cuando el id es null; encadena con H-03 al convertirlo a entero. | Token emitido con identidad inválida. | Baja | HU-0002 | Vigente | Validar `usuarioId` no nulo antes de emitir el token. |
| H-15 | H14 | JwtAuthenticationFilter.doFilterInternal (L35) | `startsWith("Bearer ")` distingue mayúsculas; RFC 6750 define el esquema como insensible. | Clientes que envían `bearer` quedan sin autenticar. | Baja | HU-0002 | Vigente | Comparar el esquema con `regionMatches(true, ...)`. |
| H-16 | H15 | JwtAuthenticationFilter.doFilterInternal (L49) | `toUpperCase()` sin `Locale`. | Resultado dependiente de la configuración regional (p. ej. turco); code smell en Sonar. | Baja | HU-0002 | Vigente | Usar `toUpperCase(Locale.ROOT)`. |
| H-17 | H17 | AuthController.login (L44), AuthController.cambiarRol (L65) | Los 400 de `@Valid` los resuelve `DefaultHandlerExceptionResolver` sin cuerpo propio. | Los mensajes de validación ("El rol no puede estar vacío.") no llegan al cliente y el formato difiere de `{"error": ...}`. | Baja | HU-0002 | Vigente | Manejar `MethodArgumentNotValidException` en el manejador global (ver H-10). |
| H-18 | H6 | AuthService.resolverRolActivo (L113), AuthController.error (L77-78) | Un usuario autenticado sin roles recibe `RolNoAsignadoException`, que se traduce a 403. | Código de estado pendiente de validar con el PO. | Por confirmar | HU-0002 | Vigente | Confirmar con el PO si corresponde 403 o 401. |
| H-19 | H19 | AuthController.validateToken (L94-95), AuthService.validateToken (L69-70) | `/validate` responde 200 con `valid:false` cuando el token es inválido o no se envía. Coincide con la documentación Swagger. | Posible discrepancia con la HU si esta exige 401. | Por confirmar | HU-0002 | Vigente | Confirmar con el PO el contrato esperado de `/validate`. |
| H-20 | H20 | AuthController.error (L79-80) | CP-11 espera 400 para credenciales inválidas; el código y Swagger responden 401. | Caso de prueba desalineado con la implementación. | Por confirmar | HU-0002 / CP-11 | Vigente | Ajustar CP-11 a 401 o acordar el cambio de contrato con el PO. |

## 4. Pendientes de definir con el PO

- H-18 (H6): definir si una cuenta autenticada sin roles asignados debe responder 403 o 401.
- H-19 (H19): definir si `/api/v1/auth/validate` debe responder 401 ante token inválido o ausente, o mantener 200 con `valid:false`.
- H-20 (H20): definir si credenciales inválidas responden 401 (implementación y Swagger) o 400 (CP-11), y actualizar el artefacto que corresponda.

## 5. Complejidad ciclomática

| Métrica | Antes (3b7f62e) | Después (583a04c) |
|---|---|---|
| Complejidad del proyecto | 73 | 49 |
| Complejidad máxima por clase | 27 (AuthService) | 15 (AuthService) |

| Clase | Complejidad |
|---|---|
| AuthService | 15 |
| AuthController | 8 |
| JwtService | 8 |
| JwtAuthenticationFilter | 6 |
| SecurityConfig | 4 |

Nota: el pipeline evalúa complexity < 50. Falta confirmar con el profesor si el límite aplica al proyecto o a la clase.

- Criterio por proyecto: se cumple (49 < 50). Antes del refactor no se cumplía (73). El margen es de 1 punto.
- Criterio por clase: se cumple (máximo 15). También se cumplía antes del refactor (máximo 27).

Valores calculados con JaCoCo 0.8.11 (suma de `COMPLEXITY_MISSED` y `COMPLEXITY_COVERED` de `jacoco.csv`). SonarCloud calcula la complejidad con su propio analizador y puede reportar valores distintos.

## 6. Notas

- Los hallazgos no se corrigen desde pruebas unitarias porque el alcance excluye el código de producción. Los de severidad Alta y Media se registran en Mantis.
- Tests ajustados por el refactor: ninguno. Los 70 tests pasan sin cambios sobre 583a04c.
- Cambio de comportamiento del refactor no cubierto por los 20 hallazgos: `AuthService.login` (L36) sustituye un usuario inexistente por `new UsuarioAuth()`. A nivel de servicio, una contraseña enviada vacía coincide con la almacenada vacía y la respuesta pasa de 401 a 403 ("El usuario no tiene roles asignados."). En HTTP lo evita `@NotBlank` en `LoginRequest`.

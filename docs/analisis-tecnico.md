# Kirowen: análisis técnico del concepto

**Versión:** 0.1
**Fecha:** 2026-11-17
**Base:** Documento conceptual «Registro Universal de Eventos Inmutables», v0.1
**Estado:** Propuesta para discusión. Nada de lo que aparece aquí como recomendación está decidido.

---

## 0. Resumen ejecutivo

1. **El modelo es coherente y viable.** No hay contradicciones de fondo. Hay tensiones concretas (privacidad frente a inmutabilidad, cadena global frente a aislamiento, gratuidad frente a abuso) y todas tienen soluciones conocidas.

2. **No hace falta blockchain.** El problema descrito coincide casi exactamente con el de los **transparency logs**: Certificate Transparency (RFC 6962 / RFC 9162), Sigstore Rekor, Go Checksum Database y Sigsum. Llevan años en producción a escala de miles de millones de entradas y con costes bajos.

3. **Propuesta central:** un log append-only basado en un **árbol de Merkle**, con un único secuenciador y estas piezas:
   - **checkpoints firmados**;
   - **pruebas de inclusión y de consistencia** de tamaño logarítmico;
   - **testigos externos** que cosignan los checkpoints;
   - **eventos firmados por las fuentes**;
   - **contenido separado del log** (el log solo guarda compromisos criptográficos).

4. **La garantía frente a un administrador malicioso (escenario 6) no puede venir del propio sistema.** Solo se consigue con algo que el operador no controla: testigos, anclaje público o verificadores que guarden checkpoints. Es la pieza más importante del diseño y también una de las más baratas.

5. **El encadenamiento lineal de hashes es necesario pero insuficiente.** Un árbol de Merkle cumple el mismo propósito y además permite pruebas compactas, verificación incremental real y privacidad en la verificación.

6. **Riesgos principales:** omisión o censura de eventos, vista dividida (*split view*), compatibilidad con el RGPD, fuga de metadatos a través de la cadena global, abuso de un servicio gratuito y la ventana sin protección entre checkpoints cuando hay poco tráfico.

---

## 1. Coherencia del modelo

### 1.1 Lo que se sostiene sin cambios

| Principio | Valoración |
|---|---|
| Append-only, correcciones como eventos nuevos | Correcto y estándar. |
| Registro agnóstico al contenido | Correcto; además simplifica mucho el sistema. |
| Secuencia global única | Viable con un único secuenciador lógico. Es lo que hacen todos los transparency logs. |
| Distinguir el momento declarado del momento de aceptación | Imprescindible y bien planteado. |
| Separar integridad, veracidad, disponibilidad y durabilidad | Es la distinción correcta. Muchos proyectos fracasan por mezclarlas. |
| Separar la verdad del registro de la verdad del mundo | Correcto. Evita prometer lo imposible. |
| La descentralización no es un objetivo en sí | Correcto. Permite elegir la solución más barata que dé las garantías. |

### 1.2 Tensiones a resolver en el diseño

**T1. Cadena global frente a aislamiento entre participantes (§6, §13).**
Si cada eslabón contiene el evento completo, verificar la cadena exige ver los eventos de todos. Para resolverlo, las hojas del log deben contener **compromisos** (hashes con sal) y no contenido. La verificación global trabaja con hashes y el contenido solo lo ven quienes tienen autorización. Detalle en §7.

**T2. Inmutabilidad frente a obligaciones legales de supresión (§13, §15).**
El RGPD (art. 17) puede obligar a borrar datos personales. Un log inmutable que contenga datos personales en claro sería incompatible con eso. La solución es la misma separación: el contenido vive fuera del árbol y se puede borrar o destruir criptográficamente (*crypto-shredding*), mientras que la hoja conserva el compromiso. El historial sigue siendo verificable («aquí hubo un evento con este hash») aunque el contenido ya no exista. Requiere una validación jurídica, porque un hash de un dato personal puede seguir considerándose dato seudonimizado.

**T3. Relación por objeto frente a privacidad de metadatos (§6, §13).**
Enlazar públicamente los eventos de un mismo objeto revela patrones a cualquiera que vea el log: cuántos eventos tiene un envío, con qué frecuencia, cuándo deja de tenerlos. Si el log es público, el enlace por objeto debe ser opaco para quien no tenga autorización (§6.3).

**T4. Checkpoints cada 1.000 eventos frente a poco tráfico (§8).**
La decisión es razonable a volumen alto. A volumen bajo (por ejemplo, 50 eventos al día) se tardarían 20 días en generar un checkpoint, y durante ese tiempo los eventos nuevos no estarían anclados externamente. No propongo cambiar la decisión, sino **complementarla** con la publicación periódica de cabeceras firmadas para los testigos. Se explica en §5.4.

**T5. Gratuidad frente a abuso (§17).**
Un servicio de escritura gratuita y permanente es un objetivo natural para spam y para el almacenamiento abusivo: si el registro acepta cualquier contenido, cualquiera puede usarlo para guardar datos sin pagar. Sin cuotas, autenticación de fuentes y límites de tamaño, el coste no está acotado. Es el riesgo económico más serio.

### 1.3 Supuestos que conviene corregir o precisar

- **«Para reconstruir una versión válida habría que recalcular todas las referencias» (§5).** Recalcular cuesta milisegundos; no es una barrera. La única barrera real es que alguien externo haya guardado el estado anterior. El documento ya lo reconoce en la «limitación reconocida», pero conviene no presentar el recálculo como un obstáculo en sí.

- **«La fuente debe autenticarse» (§10).** La autenticación (por ejemplo, con un token de API) solo demuestra al servidor quién llama. No impide que el operador **fabrique** eventos a nombre de una fuente. Para que la «verdad del registro» (§12) no dependa del operador, **la fuente debe firmar cada evento** con una clave propia.

- **«Un checkpoint representa el estado acumulado» (§8).** Con un árbol de Merkle, la raíz del árbol en cualquier tamaño ya representa ese estado. El checkpoint no es un cálculo extra, sino **la firma y la publicación** de esa raíz. Su valor depende de dónde acaba esa firma, no de calcularla.

- **«Verificar sin recorrer el historial» (§8, escenario 7).** Con una cadena lineal más checkpoints, verificar que un evento concreto está incluido sigue exigiendo recorrer el segmento. Con Merkle, la prueba ocupa unos `log₂(n)` hashes (unos 30 hashes para mil millones de eventos) y no hay que recorrer nada.

---

## 2. Modelo de amenazas

Una garantía solo tiene sentido frente a un adversario concreto.

| Actor | Capacidad | Qué puede intentar |
|---|---|---|
| **Operador del registro** (incluido un administrador malicioso o comprometido) | Control total de servidores, base de datos y claves del servicio | Modificar o borrar eventos; reescribir el historial completo; fabricar eventos; omitir eventos; enseñar historiales distintos a clientes distintos; retrasar la aceptación; filtrar contenido |
| **Fuente** | Su clave y su acceso a la API | Registrar declaraciones falsas; negar haber registrado algo; saturar el servicio; reintentar y provocar duplicados |
| **Otra fuente** | Su acceso legítimo | Leer o inferir datos ajenos; suplantar a otra fuente |
| **Atacante externo** | Red; quizá credenciales robadas | Suplantar fuentes; alterar mensajes en tránsito; comprometer el servidor (y pasar a tener las capacidades del operador) |
| **Consumidor o verificador** | Lo que le entregan; checkpoints guardados | Es la víctima potencial: necesita detectar manipulaciones sin fiarse del operador |

**Supuestos de confianza mínimos de la propuesta:**
- Las funciones hash y los esquemas de firma usados son seguros.
- La clave privada de cada fuente solo la tiene esa fuente.
- **Al menos uno** de los testigos externos que acepta el verificador es honesto y está disponible.
- El verificador guarda o puede obtener checkpoints cosignados.

Si no se cumple el tercer supuesto (no hay testigos, o todos colaboran con el operador), el escenario 6 **no** se puede garantizar. Ningún diseño puede evitarlo.

---

## 3. Garantías reales frente a garantías aparentes

| Afirmación | ¿Real? | Condición |
|---|---|---|
| «Modificar un evento rompe la cadena» | **Real**, frente a quien conserve un checkpoint posterior al evento. | Sin un checkpoint externo, el operador puede recalcularlo todo. |
| «El historial no puede reescribirse» | **Aparente** si solo hay encadenamiento. **Real** (como detección, no como imposibilidad) si hay testigos o anclaje externo. | Testigos honestos y verificadores que contrasten. |
| «El evento lo registró la fuente X» | **Aparente** con autenticación por token. **Real** si la fuente firma el evento. | Clave de la fuente no comprometida; registro de claves verificable. |
| «El contenido es correcto» | **No se garantiza**, y el documento lo reconoce (§12). | — |
| «El registro contiene todos los eventos de la fuente» | **No se garantiza** por defecto. El operador puede descartar eventos en silencio. | Mitigable con recibos firmados y números de secuencia por fuente (§5.6). |
| «El historial de este objeto está completo» | **Parcial**. Los enlaces hacia atrás prueban que no hay huecos, pero no que se haya entregado el último evento. | Completitud fuerte requiere un mapa verificable (§6.2). |
| «Todos ven el mismo historial» | **Aparente** sin testigos. Es el ataque de vista dividida. | Testigos o *gossip* de checkpoints. |
| «El evento ocurrió en el momento T» | **No se garantiza.** Es una declaración de la fuente. | — |
| «El registro aceptó el evento antes del momento T» | **Real** si el checkpoint que lo incluye está anclado en una fuente de tiempo externa (testigo con marca de tiempo, RFC 3161 u OpenTimestamps). | Fuente de tiempo fiable. |
| «Los datos estarán siempre disponibles» | **No se garantiza.** La integridad no implica disponibilidad. | Réplicas, espejos y política de retención. |
| «Verificar no revela datos ajenos» | **Real** si las hojas son compromisos con sal. | Diseño correcto de las hojas (§7). |

---

## 4. Alternativas tecnológicas

### 4.1 Opciones evaluadas

**A. Base de datos convencional + cadena lineal de hashes.**
Una tabla append-only en la que cada fila incluye el hash de la anterior.
- A favor: trivial de implementar y barata.
- En contra: no da garantías frente al operador; las pruebas de inclusión son lineales; no hay pruebas de consistencia compactas.
- Veredicto: insuficiente por sí sola. Sirve como almacenamiento subyacente, no como mecanismo de confianza.

**B. Transparency log con árbol de Merkle (RFC 6962/9162, ecosistema C2SP).**
Árbol de Merkle append-only, checkpoints firmados, pruebas de inclusión y consistencia y testigos.
- A favor: diseñado exactamente para «el operador no es de fiar, pero las manipulaciones deben ser detectables». Hay especificaciones abiertas (C2SP: `signed-note`, `tlog-checkpoint`, `tlog-tiles`, `tlog-witness`, `tlog-cosignature`) y bibliotecas maduras (Trillian Tessera en Go, Sigsum). Se puede servir como **ficheros estáticos** (*tiles*) desde almacenamiento de objetos o una CDN, que es muy barato. Las pruebas son logarítmicas.
- En contra: no resuelve por sí mismo el historial por objeto ni la privacidad; hay que diseñarlos encima. Los testigos públicos existentes están pensados para logs con cierto perfil, así que hay que confirmar si aceptarían este log o si habría que operar testigos propios con terceros.
- Veredicto: **recomendada** como núcleo.

**C. Base de datos inmutable o verificable (por ejemplo, immudb).**
Una base de datos con árbol de Merkle interno y pruebas.
- A favor: menos piezas propias; consultas tipo base de datos.
- En contra: atadura a un producto concreto; la verificación independiente depende de su formato; los testigos externos no son un ciudadano de primera. Amazon QLDB, la referencia comercial de esta categoría, se discontinuó en 2025, lo que ilustra el riesgo de depender de un producto.
- Veredicto: viable, pero la opción B da las mismas garantías con estándares abiertos y sin atadura.

**D. Blockchain permisionada (por ejemplo, Hyperledger Fabric).**
- A favor: replicación entre organizaciones.
- En contra: complejidad operativa alta, coste alto, gobernanza entre organizaciones obligatoria. Si todos los nodos los controla el mismo operador, no añade nada frente a B.
- Veredicto: no justificada en esta fase. Solo tendría sentido si varias organizaciones quisieran coadministrar el registro, y aun así los testigos de B suelen bastar.

**E. Blockchain pública como almacenamiento de los eventos.**
- En contra: cada escritura tiene coste por transacción (contradice §17 y §18), es lenta, todo es público (contradice §13) y no se puede borrar (contradice el RGPD).
- Veredicto: descartada.

**F. Blockchain pública solo como ancla de checkpoints.**
Publicar periódicamente el hash de un checkpoint en una cadena pública, por ejemplo mediante OpenTimestamps, que es gratuito y agrega muchos hashes en una sola transacción de Bitcoin.
- A favor: prueba de existencia en el tiempo muy difícil de falsificar; coste casi nulo; no expone datos.
- En contra: confirmación lenta (horas); dependencia de un servicio agregador y de la cadena.
- Veredicto: **complemento recomendado** de B, como mecanismo de testigo adicional, sin token y sin que el sistema dependa de ello para funcionar.

### 4.2 Comparativa

| Criterio | A | **B** | C | D | E | **F** (complemento) |
|---|---|---|---|---|---|---|
| Detecta reescritura por el operador | No | **Sí** (con testigos) | Parcial | Parcial | Sí | **Sí** |
| Pruebas compactas | No | **Sí** | Sí | Variable | Variable | — |
| Privacidad del contenido | Diseño propio | **Diseño propio** (compatible) | Diseño propio | Sí | No | **Sí** |
| Compatible con el RGPD | Sí | **Sí** (con contenido separado) | Sí | Complejo | No | **Sí** |
| Coste operativo | Muy bajo | **Bajo** | Bajo-medio | Alto | Muy alto | **Casi nulo** |
| Complejidad | Muy baja | **Media** | Media | Alta | Media | **Baja** |
| Estándares abiertos | — | **Sí** | Parcial | Sí | Sí | **Sí** |
| Sin token ni cripto | Sí | **Sí** | Sí | Sí | No | **Sí** (no hay que manejar ningún token) |

---

## 5. Mecanismos de verificabilidad independiente

### 5.1 Árbol de Merkle append-only

Cada evento aceptado se convierte en una **hoja** del árbol, en la posición que le asigna el secuenciador. La raíz del árbol de tamaño `N` resume criptográficamente las `N` primeras hojas.

- **Prueba de inclusión:** demuestra que la hoja `i` está en el árbol de tamaño `N` con raíz `R`. Son unos `log₂(N)` hashes.
- **Prueba de consistencia:** demuestra que el árbol de tamaño `N₂` con raíz `R₂` **extiende** al de tamaño `N₁` con raíz `R₁`, es decir, que no se ha modificado nada de lo anterior. También son unos `log₂(N₂)` hashes.

Con estas dos pruebas, un verificador que guardó `(N₁, R₁)` puede comprobar cualquier estado posterior sin descargar el historial. Ese es exactamente el escenario 7.

**Sobre el encadenamiento (decisión 4):** el árbol de Merkle cumple el propósito del encadenamiento criptográfico (cada estado depende de todos los anteriores, y alterar cualquier evento cambia todas las raíces posteriores) con propiedades mejores. Se puede añadir también a cada hoja el hash de la hoja anterior para que el encadenamiento lineal sea literal, pero no aporta garantías adicionales y añade un campo. **Propongo usar Merkle sin enlace lineal explícito**, pero es una decisión del equipo.

### 5.2 Checkpoints firmados

Un checkpoint es una declaración firmada por el registro con el formato «el árbol tiene tamaño `N` y raíz `R`». Formato sugerido: C2SP `tlog-checkpoint` sobre `signed-note`, que es texto plano, se verifica con bibliotecas existentes y lo entienden los testigos.

**Encaje con la decisión 11 (un checkpoint cada 1.000 eventos ordinarios):**
- Tras cada 1.000 eventos ordinarios, el sistema añade al log una **hoja de checkpoint** que contiene el checkpoint firmado del árbol en ese tamaño. La hoja ocupa su propia posición en la secuencia y no cuenta para los 1.000.
- Una hoja de checkpoint en la posición `N+1` certifica el árbol de tamaño `N`. No puede certificarse a sí misma, y no es un problema.
- Cada checkpoint incluye la referencia al anterior (tamaño y raíz), lo que da la «continuidad verificable entre checkpoints» que pide §8. La prueba de consistencia entre ambos la hace verificable.

**Importante:** la hoja de checkpoint dentro del log **no aporta confianza por sí sola**, como ya advierte §8. Lo que aporta confianza es la copia de ese checkpoint **cosignada por testigos y guardada fuera**.

### 5.3 Testigos externos

Un testigo es un servicio independiente con estas reglas:
1. Recibe un checkpoint nuevo y una prueba de consistencia con el último checkpoint que cosignó de ese log.
2. Solo cosigna si la prueba es válida, es decir, si el log no ha reescrito nada.
3. Guarda el último checkpoint cosignado y nunca cosigna un historial incompatible.

Un verificador solo acepta checkpoints con al menos `k` cosignaturas de testigos de su confianza. Así:
- Un operador que reescriba el historial no conseguirá cosignaturas para la versión nueva, y los verificadores la rechazarán (**escenario 6**).
- Un operador que enseñe historiales distintos a clientes distintos (*split view*) tendría que conseguir que los testigos cosignaran ambas versiones, cosa que no harán.

Especificación sugerida: C2SP `tlog-witness` y `tlog-cosignature`. Opciones para conseguir testigos, de más a menos preferible:
1. Redes de testigos públicas del ecosistema C2SP/Sigsum, si aceptan este log. **Pendiente de confirmar.**
2. Organizaciones participantes que operen un testigo, que es un proceso muy ligero.
3. Testigos operados por terceros afines (universidades, fundaciones).
4. Como mínimo, anclaje en OpenTimestamps (§4.1 F) y publicación del checkpoint en un repositorio público con historial (por ejemplo, un repositorio git espejado en varias plataformas).

### 5.4 Publicación periódica de cabeceras firmadas

Para cubrir la ventana sin anclaje a bajo volumen (T4) **sin modificar la decisión 11**, propongo distinguir dos conceptos:
- **Checkpoint (hoja interna):** cada 1.000 eventos ordinarios, tal como se decidió.
- **Cabecera publicada (externa):** un checkpoint firmado del tamaño actual del árbol, enviado a los testigos cada `T` segundos si ha habido eventos nuevos (por ejemplo, `T` = 60 s). No se inserta en el log.

Así ningún evento ordinario queda más de `T` segundos sin cosignar, y la secuencia de checkpoints internos sigue la regla acordada. **Aceptado por el equipo el 2026-11-17.**

**Regla anti-autovalidación.** Solo los eventos ordinarios disparan una validación; un evento de validación nunca dispara otra. En concreto:

- **Cabecera:** se publica solo si hay **al menos un evento ordinario nuevo** desde la última cabecera publicada. Si lo único que ha entrado desde entonces es una hoja de checkpoint, no se publica nada.
- **Checkpoint interno:** solo cuenta eventos ordinarios (decisión 11), así que un checkpoint no puede generar otro.
- **Consecuencia:** el sistema nunca produce una cadena infinita de registros que se validan unos a otros. Si no llegan eventos ordinarios, el log permanece quieto: no crece y no consume recursos.

**Matiz:** una hoja de checkpoint que llegue justo al final de una ráfaga queda sin cosignar hasta que entre el siguiente evento ordinario y se publique una cabecera nueva. No es un problema. Esa hoja no contiene datos de ninguna fuente, solo el checkpoint del árbol anterior. Ese checkpoint ya pasó por los testigos como cabecera, y cualquier verificador puede comprobar la hoja a partir de él.

### 5.5 Monitores

Un monitor es un verificador que sigue el log entero: descarga todas las hojas públicas, recalcula el árbol y comprueba la consistencia. Detecta, por ejemplo, hojas malformadas o checkpoints internos incorrectos. Como las hojas solo contienen compromisos (§7), un monitor no ve contenido privado. Cualquiera puede operar uno, y la herramienta debería ser parte del proyecto.

### 5.6 Recibos y protección frente a omisión

Problema: el operador puede aceptar un evento y luego no incorporarlo nunca.

Mitigaciones:
1. **Recibo firmado.** Al aceptar un evento, el registro devuelve un recibo firmado que contiene el hash de la hoja, la posición asignada y el momento de aceptación, con el compromiso de incorporarlo antes de un plazo máximo. Es el equivalente al SCT de Certificate Transparency. Si el evento no aparece en un checkpoint cosignado dentro del plazo, el recibo es una **prueba pública de incumplimiento**.
2. **Número de secuencia por fuente.** La fuente incluye en cada evento firmado un contador monótono propio. Un hueco en la secuencia indica una omisión, y la fuente puede detectarlo comprobando sus propios eventos.
3. **Variante más simple:** incorporación síncrona. El evento solo se confirma cuando ya está en un checkpoint. Es más lento, pero elimina el concepto de «aceptado y pendiente». Con secuenciado por lotes cada 1 s, la latencia sería aceptable para la mayoría de los casos de uso.

Recomiendo empezar por la variante 3 más el contador por fuente, y añadir recibos si la latencia se convierte en un problema.

---

## 6. Historial por objeto

### 6.1 Identificación

Un objeto se identifica por el par `(fuente, id_objeto)`. Dos fuentes pueden usar el mismo `id_objeto` sin colisión. Requisito de §6 y §10.

### 6.2 Opciones para la relación por objeto

**Opción 1: enlace hacia atrás dentro del evento.**
Cada evento firmado por la fuente incluye `objeto_seq` (contador por objeto) y `prev_objeto`, que es la posición o el hash del evento anterior del mismo objeto.
- Prueba que no hay huecos entre los eventos devueltos.
- **No prueba** que se haya devuelto el último evento. Un operador podría ocultar los más recientes.
- Coste: dos campos por evento. Lo calcula la fuente, que es quien mejor conoce su objeto.

**Opción 2: mapa verificable (árbol de Merkle disperso).**
Además del log, se mantiene un mapa `objeto → último evento` comprometido criptográficamente, y su raíz va en cada checkpoint.
- Prueba la completitud: «en el checkpoint `N`, el último evento del objeto era el de la posición `p`».
- Coste: complejidad notable (la técnica de *verifiable log-backed maps* es menos madura) y más almacenamiento.

**Propuesta:** opción 1 en la primera versión. La opción 2 solo se añade si algún caso de uso necesita probar la completitud frente a terceros. Para la propia fuente, el contador por objeto ya basta, porque sabe cuántos eventos emitió.

### 6.3 Privacidad del enlace

Si las hojas son públicas, `prev_objeto` y el identificador del objeto no deben aparecer en claro en la hoja. Van dentro del **sobre del evento** (§7), cuyo hash es lo único que entra en la hoja. El índice `objeto → posiciones` lo mantiene el registro para servir consultas autorizadas, y no forma parte de los datos públicos.

---

## 7. Privacidad y aislamiento

### 7.1 Estructura en tres capas

```
┌──────────────────────────────────────────────────────────┐
│ HOJA DEL LOG (pública, inmutable)                        │
│   tipo · hash(sobre)                                     │
├──────────────────────────────────────────────────────────┤
│ SOBRE DEL EVENTO (firmado por la fuente; acceso          │
│ restringido; inmutable salvo destrucción criptográfica)  │
│   fuente · id_objeto · objeto_seq · prev_objeto ·        │
│   fuente_seq · momento_declarado · tipo_contenido ·      │
│   hash(contenido + sal) · referencias · firma            │
│   + metadatos de aceptación añadidos por el registro     │
├──────────────────────────────────────────────────────────┤
│ CONTENIDO (opaco; acceso restringido; borrable)          │
│   bytes arbitrarios, cifrados en reposo                  │
└──────────────────────────────────────────────────────────┘
```

Los campos son orientativos. El formato definitivo está pendiente (§20 del concepto).

### 7.2 Propiedades resultantes

- **Verificación global sin datos:** los testigos y los monitores solo manejan hashes de sobres.
- **Prueba de inclusión sin fugas:** la prueba para el evento de una fuente solo contiene hashes de nodos hermanos y no revela nada de otras fuentes (**escenario 8**).
- **Sal obligatoria:** sin sal, un contenido como `"23.0 °C"` o `"entregado"` se puede adivinar por fuerza bruta a partir de su hash. La sal la genera la fuente y viaja con el contenido.
- **Supresión:** borrar el contenido (y, si hace falta, el sobre) deja la hoja intacta. El árbol sigue siendo verificable y el evento se vuelve «existió, pero su contenido ya no está disponible». Otra opción es cifrar cada contenido con una clave por objeto o por fuente y destruir la clave.
- **Metadatos:** aunque el contenido esté oculto, el log público revela cuántos eventos se aceptan y a qué ritmo. Si eso es sensible para alguna fuente, la mitigación es agregar en lotes (la granularidad pública pasa a ser el lote) o no publicar las hojas y publicar solo los checkpoints. Es una decisión de producto.

### 7.3 Control de acceso

Hay que separar cuatro cosas: **existencia** (pública: la hoja), **identificación** (restringida: el sobre), **contenido** (restringido) y **derecho a consultar** (política por fuente). Modelo inicial sugerido: cada fuente es dueña de sus objetos y concede lectura mediante credenciales; el registro aplica la política. Más adelante se puede añadir cifrado de extremo a extremo (la fuente cifra y el registro nunca ve el contenido en claro). Es compatible con todo lo anterior, porque el registro solo necesita el hash.

---

## 8. Identidad, firmas y claves

- **Firma de eventos:** Ed25519 como opción por defecto (rápida, firmas pequeñas y amplio soporte). El hash será SHA-256 por compatibilidad con RFC 6962/C2SP.
- **Registro de claves de fuentes dentro del propio log:** las altas, rotaciones y revocaciones de claves de cada fuente se registran como eventos de una fuente especial del sistema. Así, saber qué clave era válida para una fuente en el momento `N` también es verificable y el operador no puede cambiar claves en silencio.
- **Codificación canónica:** para que firma y hash sean reproducibles, el sobre necesita una serialización determinista. Las candidatas son CBOR determinista (RFC 8949 §4.2) o JSON canónico (RFC 8785). Está pendiente de decidir.
- **Clave del registro:** firma los checkpoints y los recibos. Debería estar en hardware o en un KMS. Su compromiso permitiría firmar checkpoints falsos, pero los testigos lo detectarían igualmente, porque no cosignarían un historial inconsistente.
- **Algoritmos sustituibles:** cada estructura incluye un identificador de algoritmo, para poder migrar (por ejemplo, a firmas poscuánticas) sin romper el historial.

---

## 9. Concurrencia, orden y fallos

- **Secuenciador único lógico.** Las peticiones concurrentes entran en una cola. El secuenciador asigna posiciones de forma estrictamente monótona, por lotes (por ejemplo, cada 1 s o cada `M` eventos), calcula el nuevo árbol y publica. Esto garantiza que dos eventos confirmados nunca comparten posición (§14).
- **Rendimiento esperado:** las implementaciones actuales de este patrón procesan miles de eventos por segundo en una sola máquina modesta. Habría que confirmarlo con una prueba propia.
- **Idempotencia y reintentos:** cada evento lleva un identificador de idempotencia asignado por la fuente. Si se reintenta `(fuente, id_idempotencia)`, el registro devuelve la confirmación original sin duplicar el evento.
- **Tres momentos (§14):**
  - `momento_declarado`: firmado por la fuente, no verificable.
  - `momento_recibido`: lo registra el servidor, de confianza limitada.
  - `momento_aceptado`: el del lote; está acotado externamente por la cosignatura del testigo o el ancla.
- **Fallo del secuenciador:** como el estado es el propio log y está en almacenamiento duradero, la recuperación consiste en reanudar desde el último lote persistido. Lo que no esté en un lote persistido no se había confirmado, y la fuente reintenta.
- **Alta disponibilidad de escritura:** en la primera versión, un único secuenciador activo con recuperación rápida. Montar varios secuenciadores con consenso (por ejemplo, Raft) añade una complejidad que solo se justifica si hace falta disponibilidad de escritura muy alta.

---

## 10. Disponibilidad, durabilidad y recuperación

- **Log como ficheros estáticos (*tiles*, C2SP `tlog-tiles`).** El árbol y las hojas se publican como ficheros inmutables en almacenamiento de objetos. La lectura escala con una CDN a coste muy bajo, y **cualquiera puede espejar el log** copiando ficheros. Eso da durabilidad independiente del operador.
- **Separar el almacenamiento de lo público y de lo privado:**
  - Log público (hojas y árbol): replicable sin restricciones.
  - Sobres y contenido: réplicas controladas, cifradas, en al menos dos proveedores o regiones.
- **Lo que se pierde si cae el operador:** el contenido privado, salvo que las fuentes conserven su propia copia (es recomendable que lo hagan). Las pruebas públicas sobreviven en espejos y testigos.
- **Retención:** hace falta una política explícita (por ejemplo, contenido conservado `X` años y luego borrado, hojas conservadas indefinidamente porque ocupan poco). Está pendiente (§20 del concepto).

---

## 11. Costes

Estimaciones de orden de magnitud para validar con una prueba. Los precios de proveedores cambian.

**Tamaño por evento:**
- Hoja: unos 40 bytes (tipo más hash).
- Sobre: unos 300 a 500 bytes (metadatos más firma).
- Contenido: variable. **Hay que limitar su tamaño.** Para documentos grandes se registra solo su hash (§11 del concepto).

**Escenario de 1 millón de eventos al día, con contenido medio de 500 bytes:**
- Unos 1 GB al día y unos 365 GB al año en total.
- Las hojas y el árbol público suponen menos del 10 % de eso.
- Cómputo: una VM pequeña basta para el secuenciador y la API.
- Almacenamiento de objetos: decenas de euros al mes al cabo de un año.
- Total: probablemente **decenas de euros al mes**. El coste dominante es el almacenamiento del contenido, no la criptografía.

**Lo que puede disparar el coste:**
- Abuso del servicio gratuito (T5): requiere cuotas por fuente, límites de tamaño, alta de fuentes y limitación de peticiones desde el primer día.
- Retención indefinida de contenido.
- Requisitos de alta disponibilidad de escritura.
- Operar testigos propios. Es barato, pero necesita operadores **independientes**, lo cual es un problema organizativo más que de dinero.

**Lo que es prácticamente gratis:** los testigos externos (si se consiguen), el anclaje en OpenTimestamps y el servicio de lectura del log público por CDN.

---

## 12. Arquitectura propuesta

### 12.1 Componentes

```
          Fuentes (firman eventos)
                    │
                    ▼
       ┌─────────────────────────┐
       │ API de ingesta          │ auth · cuotas · validación de firma
       │                         │ · idempotencia
       └────────────┬────────────┘
                    ▼
       ┌─────────────────────────┐      ┌──────────────────────┐
       │ Secuenciador            │─────▶│ Almacén de sobres    │
       │ (lotes, posición,       │      │ y contenido          │
       │ árbol, checkpoints      │      │ (privado, cifrado,   │
       │ cada 1.000)             │      │ borrable)            │
       └────────────┬────────────┘      └──────────▲───────────┘
                    ▼                              │
       ┌─────────────────────────┐      ┌──────────┴───────────┐
       │ Log público (tiles)     │      │ Índice por objeto    │
       │ almacenamiento de       │      │ (fuente,id) →        │
       │ objetos + CDN           │      │ posiciones           │
       └──┬──────────────────┬───┘      └──────────▲───────────┘
          │                  │                     │
          ▼                  ▼                     │
  ┌──────────────┐   ┌──────────────┐   ┌──────────┴───────────┐
  │ Testigos     │   │ Espejos /    │   │ API de consulta      │
  │ externos     │   │ monitores    │   │ (historial, pruebas, │
  │ (cosignan)   │   │              │   │ checkpoints)         │
  └──────┬───────┘   └──────────────┘   └──────────────────────┘
         ▼
  Checkpoints cosignados ──▶ verificadores (biblioteca/CLI abierta)
         └──▶ anclaje opcional (OpenTimestamps / repositorio público)
```

### 12.2 Flujos principales

**Registrar un evento:**
1. La fuente construye el sobre, calcula `hash(contenido + sal)`, lo firma y lo envía junto con el contenido.
2. La API valida la firma contra la clave registrada de la fuente, aplica cuotas y comprueba la idempotencia.
3. El secuenciador incluye el evento en el siguiente lote, le asigna una posición, actualiza el árbol, persiste y publica.
4. La fuente recibe la confirmación: posición, hash de la hoja, checkpoint y prueba de inclusión.
5. El checkpoint se envía a los testigos, que lo cosignan. La fuente puede esperar a las cosignaturas si quiere la garantía completa.

**Consultar el historial de un objeto:**
La API devuelve, a quien tenga autorización, los sobres y el contenido del objeto con sus pruebas de inclusión. El cliente verifica las firmas, las inclusiones y la continuidad de `objeto_seq` y `prev_objeto`.

**Verificar (cualquier tercero):**
1. Obtiene el checkpoint más reciente cosignado por al menos `k` testigos de su confianza.
2. Comprueba la consistencia con el último checkpoint que guardó.
3. Para un evento concreto, comprueba su inclusión en ese checkpoint y la firma de la fuente.

**Derivar el estado:**
No forma parte del registro. Lo hace la aplicación, o una biblioteca cliente opcional, reproduciendo los eventos (§7 y §22 del concepto).

### 12.3 Qué hace y qué no hace el registro

| Hace | No hace |
|---|---|
| Ordenar, conservar, demostrar inclusión y consistencia | Interpretar contenido ni reglas de negocio |
| Verificar la firma de la fuente | Validar la veracidad de las declaraciones |
| Aplicar control de acceso y cuotas | Derivar estados (salvo una biblioteca cliente opcional) |
| Publicar checkpoints y recogerlos cosignados | Garantizar disponibilidad perpetua del contenido |

---

## 13. Cumplimiento de los criterios de éxito (§21 del concepto)

| Escenario | Cómo se cumple | Condición |
|---|---|---|
| 1. Múltiples fuentes | Secuenciador único con cola y posiciones monótonas | — |
| 2. Historial individual | Índice por `(fuente, id_objeto)` y control de acceso | Autorización |
| 3. Actualización | Append-only; nunca hay operación de actualización | — |
| 4. Corrección | Evento nuevo con `referencias` al corregido | Convención de la aplicación |
| 5. Modificación fraudulenta | Cambia el hash de la hoja y la prueba de inclusión falla frente al checkpoint guardado | Verificador con un checkpoint posterior |
| 6. Reconstrucción fraudulenta | La prueba de consistencia falla y los testigos no cosignan la nueva historia | **Al menos un testigo honesto** |
| 7. Validación incremental | Prueba de consistencia entre checkpoints; inclusión logarítmica | — |
| 8. Privacidad | Hojas con compromisos con sal; las pruebas no revelan datos ajenos | Diseño de §7 |

---

## 14. Riesgos

| # | Riesgo | Impacto | Mitigación |
|---|---|---|---|
| R1 | No conseguir testigos independientes | Sin ellos, el escenario 6 no se cumple | Empezar con OpenTimestamps y un repositorio público; buscar testigos entre los participantes y la comunidad C2SP |
| R2 | El operador omite eventos | Historial incompleto sin que nadie lo detecte | Confirmación síncrona, contador por fuente, recibos |
| R3 | Vista dividida | Clientes con historias distintas | Testigos; los clientes solo aceptan checkpoints cosignados |
| R4 | Incumplimiento del RGPD | Riesgo legal | Contenido fuera del árbol, borrable; revisión jurídica |
| R5 | Fuga de metadatos | Exposición de patrones de uso | Sobres no públicos; agregación por lotes |
| R6 | Abuso del servicio gratuito | Coste sin límite | Alta de fuentes, cuotas, límites de tamaño desde la primera versión |
| R7 | Compromiso de la clave de una fuente | Eventos falsos a su nombre | Rotación y revocación registradas en el log; detección por contador |
| R8 | Compromiso de la clave del registro | Checkpoints falsos | Testigos (no cosignan incoherencias); KMS o HSM |
| R9 | Errores criptográficos propios | Garantías falsas | Usar especificaciones y bibliotecas existentes; no inventar estructuras |
| R10 | Ventana sin anclar a bajo volumen | Eventos recientes reescribibles | Cabeceras publicadas periódicamente (§5.4) |
| R11 | Pérdida del operador | Contenido privado inaccesible | Espejos del log público; las fuentes conservan su copia; réplicas |
| R12 | Interpretación de «inmutable» por los usuarios | Expectativas falsas («es imposible modificarlo») | Documentar con precisión: detección, no imposibilidad (§9 del concepto) |

---

## 15. Decisiones que se proponen

Son **propuestas**. Requieren confirmación.

1. Núcleo basado en un **transparency log de Merkle** (RFC 6962/9162, C2SP). No se usa blockchain.
2. SHA-256 y Ed25519 por defecto, con identificadores de algoritmo.
3. Los **eventos los firma la fuente**. Las claves de las fuentes se registran en el propio log.
4. **Hojas = compromisos**. Sobre y contenido fuera del árbol; contenido con sal y borrable.
5. Checkpoints internos cada 1.000 eventos ordinarios (decisión 11) **y** publicación periódica de cabeceras a los testigos, solo si hay eventos ordinarios nuevos (regla anti-autovalidación, §5.4). **Aceptada.**
6. **Testigos externos** según C2SP `tlog-witness`, con anclaje en OpenTimestamps como complemento.
7. Historial por objeto con `objeto_seq` y `prev_objeto` en el sobre. El mapa verificable queda para más adelante.
8. Confirmación síncrona por lotes en la primera versión. Recibos asíncronos si la latencia lo exige.
9. Log público servido como *tiles* estáticos desde almacenamiento de objetos.
10. Cuotas y alta de fuentes obligatorias desde el primer día.

## 16. Preguntas para el equipo

1. ¿Deben ser públicas las hojas del log (cualquiera puede monitorizar) o solo los checkpoints?
2. ¿Hay que añadir el enlace lineal explícito a la hoja anterior (decisión 4 al pie de la letra), o basta el árbol de Merkle?
3. ¿Qué latencia de confirmación es aceptable: 1 s, 10 s, minutos?
4. ¿Qué tamaño máximo de contenido por evento?
5. ¿Qué política de retención de contenido?
6. ¿Quién podría operar testigos: participantes, terceros, ambos?
7. ¿Se aceptan fuentes anónimas o toda fuente requiere alta?
8. ¿Hace falta probar la completitud del historial de un objeto frente a terceros (mapa verificable)?
9. ¿El cifrado de extremo a extremo es un requisito o una mejora futura?
10. Lenguaje de implementación. Go tiene el ecosistema más maduro (Tessera, Sigsum, bibliotecas C2SP); Rust es una alternativa con buenas bibliotecas criptográficas.

## 17. Plan por fases

**Fase 0: prueba de concepto (verificable de punta a punta).**
- Secuenciador, árbol de Merkle, checkpoints internos cada 1.000 eventos, tiles en disco.
- Sobres firmados por la fuente, contenido separado.
- CLI de verificación: inclusión, consistencia y firmas.
- Demostración de los escenarios 1 a 5 y 7.

**Fase 1: confianza externa.**
- Testigo de referencia (uno propio y al menos uno operado por un tercero).
- Cabeceras periódicas y anclaje en OpenTimestamps.
- Demostración de los escenarios 6 y 8.

**Fase 2: servicio.**
- API de ingesta y consulta con autenticación, cuotas y control de acceso.
- Índice por objeto, idempotencia, registro de claves de fuentes.
- Almacenamiento en la nube y CDN; monitor y espejo.

**Fase 3: endurecimiento.**
- Política de retención y supresión, revisión jurídica.
- KMS o HSM, réplicas, alta disponibilidad si se justifica.
- Mapa verificable y cifrado de extremo a extremo si se justifican.

---

## Referencias

- RFC 6962: *Certificate Transparency*.
- RFC 9162: *Certificate Transparency Version 2.0*.
- C2SP (Community Cryptography Specification Project): `signed-note`, `tlog-checkpoint`, `tlog-tiles`, `tlog-witness`, `tlog-cosignature`.
- Trillian Tessera: biblioteca Go para transparency logs basados en tiles.
- Sigsum: transparency log minimalista con testigos.
- Sigstore Rekor: transparency log para firmas de software.
- OpenTimestamps: anclaje de marcas de tiempo en Bitcoin sin coste para el usuario.
- RFC 3161: *Time-Stamp Protocol*.
- RFC 8949 §4.2: CBOR determinista. RFC 8785: JSON Canonicalization Scheme.
- Crosby & Wallach (2009): *Efficient Data Structures for Tamper-Evident Logging*.

*Las referencias a proyectos y servicios externos reflejan el estado conocido a la fecha del documento. Hay que confirmar su disponibilidad y su estado antes de adoptarlos.*

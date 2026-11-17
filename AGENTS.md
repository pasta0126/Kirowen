# AGENTS.md

Guía para agentes (Claude, Codex, etc.) que trabajen en este repositorio.

## Qué es Kirowen

Kirowen es una infraestructura universal de **registro de eventos inmutables**. Recibe eventos de sistemas independientes, los ordena en una secuencia global única y garantiza criptográficamente que el historial no se puede modificar ni borrar **sin que se detecte**.

Principio central: **los eventos se añaden, nunca se sobrescriben. El pasado permanece verificable y los cambios generan nuevos acontecimientos.**

No es una criptomoneda, ni un token, ni un sistema de NFT, ni una plataforma financiera.

## Estado actual

**Fase de análisis y diseño. Todavía no hay código.**

- `docs/analisis-tecnico.md`: análisis técnico del concepto v0.1. Incluye garantías reales frente a aparentes, alternativas, una propuesta de arquitectura, riesgos y preguntas abiertas.
- El documento conceptual v0.1 es la fuente de los requisitos. Si no está en `docs/`, pídeselo al usuario.

## Decisiones tomadas (no re-litigar)

1. Infraestructura universal, agnóstica al contenido, para fuentes independientes.
2. Secuencia global lógica única de eventos confirmados.
3. Eventos encadenados criptográficamente y de solo adición. Las correcciones son eventos nuevos.
4. Historial individual reconstruible por objeto. Los objetos se identifican dentro del ámbito de su fuente.
5. Checkpoints automáticos: **uno cada 1.000 eventos ordinarios**. Los checkpoints no cuentan en esos 1.000 y ocupan su propia posición en la secuencia.
6. Verificabilidad criptográfica independiente: una reconstrucción por un administrador debe ser detectable por verificadores que guarden pruebas.
7. Separar integridad, veracidad, disponibilidad y durabilidad.
8. Publicación periódica de cabeceras firmadas a los testigos externos cada `T` segundos, como complemento de los checkpoints (ver `docs/analisis-tecnico.md` §5.4).
9. **Regla anti-autovalidación:** solo los eventos ordinarios disparan validaciones. Si desde la última validación no hay eventos ordinarios nuevos, no se genera otra. Nunca puede formarse una cadena infinita de registros que se validan a sí mismos.
10. Sin criptomoneda ni token. Coste operativo mínimo, con la aspiración de ofrecer el servicio gratis.

## Decisiones abiertas (no presuponer)

Nombre definitivo, lenguaje, almacenamiento, uso o descarte de blockchain, algoritmos, identidad y firmas, testigos externos, formatos de evento, privacidad y retención, replicación, gobernanza y modelo económico.

`docs/analisis-tecnico.md` §15 contiene **propuestas**, no decisiones. No las trates como requisitos hasta que el usuario las confirme.

## Normas de trabajo

- **Idioma:** la documentación y la conversación van en español. Los identificadores de código pueden ir en inglés.
- **Precisión en las garantías:** no afirmes que algo es «imposible de modificar». El sistema garantiza **detección** bajo supuestos de confianza explícitos, que hay que decir siempre.
- **No inventar criptografía:** usa especificaciones y bibliotecas existentes (RFC 6962/9162, C2SP) en lugar de estructuras propias.
- **Simplicidad:** solo se justifica una tecnología o pieza si aporta una garantía que no se consigue de forma más simple y barata.
- **El registro no interpreta el negocio:** las reglas de interpretación de los eventos son de las aplicaciones, no del registro.
- **Cambios de diseño:** cuando una propuesta afecte a una decisión tomada, señala la tensión y deja que el usuario decida.

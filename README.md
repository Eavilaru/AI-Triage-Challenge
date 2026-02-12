# AI Triage Agent - Documentación de Arquitectura

Este repositorio contiene la implementación de un Agente de Validación de Seguridad Asistido por IA diseñado para filtrar falsos positivos de herramientas SAST y priorizar vulnerabilidades reales.

## Descripción General

El sistema actúa como un verificador automatizado. Recibe un reporte de hallazgos, analiza el código fuente relevante utilizando análisis estático determinista y razonamiento de LLM, y genera un veredicto (True/False Positive) con evidencia técnica.

## Arquitectura de la Solución

La solución sigue una arquitectura modular compuesta por cuatro capas principales:

1.  Capa de Entrada (CLI):
    *   Archivo: `cli.py`
    *   Función: Procesa archivos JSON de vulnerabilidades (individuales o por lotes), gestiona argumentos de línea de comandos y configura el entorno.
    *   Salida: Informes duales en JSON y HTML.

2.  Capa de Agente (Orquestador AI):
    *   Archivo: `agent/security_agent.py`
    *   Función: Cerebro del sistema. Utiliza OpenAI GPT-4o para razonar sobre el código.
    *   Flujo:
        1.  Recibe el hallazgo.
        2.  Decide qué herramientas ejecutar (Function Calling).
        3.  Analiza los resultados de las herramientas.
        4.  Genera un veredicto estructurado (JSON) en español.

3.  Capa de Herramientas (Tools):
    *   Carpeta: `tools/`
    *   Filosofía: Ejecución determinista y segura (sin alucinaciones en la recolección de datos).
    *   Lista de Herramientas:
        *   `code_context_tool`: Extrae fragmentos de código alrededor de las líneas reportadas.
        *   `taint_trace_tool`: Utiliza el módulo `ast` de Python para rastrear flujo de datos intra-procedural (variables, asignaciones).
        *   `sink_detector_tool`: Verifica si una función vulnerable (sink) está presente usando patrones conocidos.
        *   `sanitizer_detector_tool`: Busca funciones de limpieza o validación (ej. queries parametrizadas).

4.  Capa de Reporte:
    *   Archivo: `reporting/report_generator.py`
    *   Función: Transforma el análisis estructurado en formatos legibles por humanos y máquinas (HTML/JSON), incluyendo trazas y justificaciones.

## Tecnologías y Modelos Utilizados

### Modelo de IA
*   Modelo: GPT-4o (OpenAI).
*   Rol: Razonamiento de seguridad, comprensión de código y síntesis de reportes.
*   Configuración: Temperature 0, Output JSON Mode.

### Herramientas y Librerías (Stack Tecnológico)
*   Lenguaje: Python 3.10+
*   Librerías Clave:
    *   `openai`: Cliente para la API de GPT-4o.
    *   `pydantic`: Validación de esquemas de datos y estructuración de I/O.
    *   `ast`: Módulo nativo de Python para análisis de sintaxis (Abstract Syntax Tree).
    *   `sqlite3`: Para pruebas de concepto de base de datos.
    *   `requests`: Utilizado en la detección de SSRF.

## Formato del Archivo de Entrada (`findings.json`)

El archivo de entrada debe ser un JSON que contenga una lista de vulnerabilidades.


## Cómo Ejecutar

1.  Instalar dependencias:
    ```bash
    pip install openai pydantic requests
    ```

2.  Configurar API Key:
    *   **Opción A (.env):** Crea un archivo `.env` en la raíz con:
        ```env
        OPENAI_API_KEY=sk-...
        ```
    *   **Opción B (Variable de Entorno):**
        ```powershell
        $env:OPENAI_API_KEY="sk-..."
        ```

3.  Ejecutar Análisis:
    Debes especificar explícitamente el archivo de hallazgos y el archivo fuente Python:

    ```bash
    python cli.py sample/findings.json --source sample/sample.py --output reports/auditoria_final.html
    ```

4.  Ver Resultados:
    Los reportes se generarán en `reports/auditoria_final.html` y `reports/auditoria_final.json`.

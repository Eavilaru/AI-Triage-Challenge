from pydantic import BaseModel, Field


class SinkDetectorInput(BaseModel):
    snippet: str = Field(..., description="Bloque de código a analizar")
    vulnerability_type: str = Field(..., description="Tipo de vulnerabilidad reportada")


class SinkDetectionOutput(BaseModel):
    sink_detected: bool
    sink_type: str
    explanation: str


def sink_detector_tool(input_data: SinkDetectorInput) -> SinkDetectionOutput:
    """
    Detecta si existen patrones de sinks peligrosos conocidos en el snippet.
    """
    snippet = input_data.snippet.lower()

    sink_detected = False
    sink_type = "Unknown"
    explanation = "No se detectó un sink conocido."

    SINKS = {
        "sql injection": ["execute", "cursor", "raw_sql", "executemany"],
        "command injection": ["system", "popen", "subprocess", "call", "run"],
        "xss": ["render_template_string", "response", "markup"],
        "ssrf": ["requests.get", "requests.post", "urlopen", "httpclient", "get"]
    }

    vuln_type_key = input_data.vulnerability_type.lower()
    patterns = SINKS.get(vuln_type_key, [])
    
    if not patterns:
        if "sql" in vuln_type_key: patterns = SINKS["sql injection"]
        elif "command" in vuln_type_key or "rce" in vuln_type_key: patterns = SINKS["command injection"]
        elif "xss" in vuln_type_key: patterns = SINKS["xss"]
        elif "ssrf" in vuln_type_key: patterns = SINKS["ssrf"]

    for pattern in patterns:
        if pattern in snippet:
            sink_detected = True
            sink_type = pattern
            explanation = f"Se detectó un patrón de sink peligroso: '{pattern}' asociado a {input_data.vulnerability_type}."
            break
            
    if not sink_detected:
         if "execute" in snippet or "eval" in snippet:
             sink_detected = True
             sink_type = "Generic Execution"
             explanation = "Se detectó ejecución genérica potencialmente peligrosa."

    return SinkDetectionOutput(
        sink_detected=sink_detected,
        sink_type=sink_type,
        explanation=explanation
    )

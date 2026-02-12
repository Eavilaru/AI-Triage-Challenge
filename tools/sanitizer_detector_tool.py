from pydantic import BaseModel, Field
from typing import List


class SanitizerDetectorInput(BaseModel):
    snippet: str = Field(..., description="Bloque de código a analizar")
    vulnerability_type: str = Field(..., description="Tipo de vulnerabilidad reportada")


class SanitizerDetectionOutput(BaseModel):
    sanitizers_found: List[str]
    sufficient: bool
    explanation: str


def sanitizer_detector_tool(input_data: SanitizerDetectorInput) -> SanitizerDetectionOutput:
    """
    Identifica mecanismos de sanitización o validación en el código.
    """
    snippet = input_data.snippet.lower()

    sanitizers_found = []
    sufficient = False
    explanation = "No se detectaron sanitizers relevantes."

    SANITIZERS = {
        "sql injection": [
            {"pattern": "?", "name": "Parameterized Query (Placeholder)"},
            {"pattern": "%s", "name": "Parameterized Query (Placeholder Postgres/MySQL)"},
            {"pattern": ":", "name": "Named Parameter"},
            {"pattern": "literal", "name": "SQLAlchemy Literal"}
        ],
        "command injection": [
            {"pattern": "shlex.quote", "name": "Shell Escape"},
            {"pattern": "subprocess.run", "name": "Subprocess List Args (Implicit)"} 
        ],
        "xss": [
            {"pattern": "escape", "name": "HTML Escape"},
            {"pattern": "bleach", "name": "Bleach Sanitizer"}
        ]
    }

    vuln_type_key = input_data.vulnerability_type.lower()
    checks = SANITIZERS.get(vuln_type_key, [])
    
    if not checks:
        if "sql" in vuln_type_key: checks = SANITIZERS["sql injection"]

    for check in checks:
        if check["pattern"] in snippet:
            sanitizers_found.append(check["name"])
            sufficient = True
            explanation = f"Se detectó mitigación: {check['name']}."

    return SanitizerDetectionOutput(
        sanitizers_found=sanitizers_found,
        sufficient=sufficient,
        explanation=explanation
    )

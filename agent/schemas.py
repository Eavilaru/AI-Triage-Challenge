from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class TracePath(BaseModel):
    file: str = Field(..., description="Archivo donde ocurre la vulnerabilidad")
    function: str = Field(..., description="Función afectada")
    source_line: int = Field(..., description="Línea donde entra el input controlado por el usuario")
    sink_line: int = Field(..., description="Línea donde ocurre el sink vulnerable")
    flow: List[str] = Field(
        ...,
        description="Variables o pasos intermedios desde source hasta sink"
    )


class SanitizerInfo(BaseModel):
    name: str = Field(..., description="Nombre del sanitizer o validador detectado")
    line: int = Field(..., description="Línea donde se aplica el sanitizer")
    sufficient: bool = Field(
        ...,
        description="Indica si el sanitizer es suficiente para prevenir la explotación"
    )
    explanation: str = Field(
        ...,
        description="Explicación técnica de por qué es suficiente o insuficiente"
    )


class VulnerabilityAnalysis(BaseModel):
    id: str = Field(..., description="Identificador único del hallazgo")

    classification: Literal["True Positive", "False Positive"] = Field(
        ...,
        description="Clasificación final del hallazgo"
    )

    severity: Literal["Low", "Medium", "High", "Critical"] = Field(
        ...,
        description="Nivel de severidad asignado según impacto"
    )

    trace: TracePath = Field(
        ...,
        description="Trazabilidad completa desde source hasta sink"
    )

    sanitizers: List[SanitizerInfo] = Field(
        default_factory=list,
        description="Lista de sanitizers detectados en el flujo"
    )

    assumptions: List[str] = Field(
        ...,
        description="Supuestos explícitos realizados durante el análisis"
    )

    justification: str = Field(
        ...,
        description="Explicación detallada del análisis y decisión tomada"
    )

    counterexample: Optional[str] = Field(
        None,
        description="Contraejemplo mínimo que demuestra no explotabilidad si es False Positive"
    )

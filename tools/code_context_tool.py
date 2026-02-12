from pydantic import BaseModel, Field
from typing import Optional
import os


class CodeContextInput(BaseModel):
    file_path: str = Field(..., description="Ruta del archivo a analizar")
    source_line: int = Field(..., description="Línea donde entra el input controlado")
    sink_line: int = Field(..., description="Línea donde ocurre el sink vulnerable")
    context_radius: int = Field(
        5,
        description="Número de líneas adicionales antes y después para contexto"
    )


class CodeContextOutput(BaseModel):
    snippet: str
    function_name: Optional[str]
    start_line: int
    end_line: int


def code_context_tool(input_data: CodeContextInput) -> CodeContextOutput:
    """
    Recupera un fragmento de código alrededor de las líneas de interés.
    """
    if not os.path.exists(input_data.file_path):
        raise FileNotFoundError(f"File not found: {input_data.file_path}")

    with open(input_data.file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    start = max(0, input_data.source_line - input_data.context_radius - 1)
    end = min(len(lines), input_data.sink_line + input_data.context_radius)

    snippet = "".join(lines[start:end])

    function_name = None
    for i in range(start, -1, -1):
        if lines[i].strip().startswith("def "):
            function_name = lines[i].strip().split("(")[0].replace("def ", "")
            break

    return CodeContextOutput(
        snippet=snippet,
        function_name=function_name,
        start_line=start + 1,
        end_line=end
    )

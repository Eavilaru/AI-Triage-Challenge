import json
import logging
import os
from typing import Optional, Dict, Any, List

from openai import OpenAI
from pydantic import ValidationError

from agent.schemas import VulnerabilityAnalysis
from agent.tool_registry import SmartToolRegistry
from tools.code_context_tool import (
    CodeContextInput,
    code_context_tool,
)
from tools.taint_trace_tool import (
    TaintTraceInput,
    taint_trace_tool,
)
from tools.sink_detector_tool import (
    SinkDetectorInput,
    sink_detector_tool,
)
from tools.sanitizer_detector_tool import (
    SanitizerDetectorInput,
    sanitizer_detector_tool,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityValidationAgent:
    """
    Agente que orquesta el análisis de vulnerabilidades utilizando Function Calling.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Inicializa el agente con un cliente de OpenAI y registra las herramientas.
        """
        if api_key:
            self.client = OpenAI(api_key=api_key)
        else:
            self.client = OpenAI()

        self.registry = SmartToolRegistry()
        self._register_tools()

    def _register_tools(self):
        """Registra las herramientas disponibles para el agente."""
        self.registry.register("get_code_context", code_context_tool, CodeContextInput)
        self.registry.register("detect_taint_flow", taint_trace_tool, TaintTraceInput)
        self.registry.register("detect_sink", sink_detector_tool, SinkDetectorInput)
        self.registry.register("detect_sanitizers", sanitizer_detector_tool, SanitizerDetectorInput)

    def analyze_vulnerability(
        self,
        vulnerability_id: str,
        file_path: str,
        vulnerability_type: str,
        source_line: int,
        sink_line: int,
        message: str,
    ) -> VulnerabilityAnalysis:
        """
        Punto de entrada principal para analizar una vulnerabilidad.
        """
        system_prompt = self._construct_system_prompt()
        user_prompt = self._construct_user_prompt(
            vulnerability_id, file_path, vulnerability_type, source_line, sink_line, message
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        tools_schema = self.registry.get_tool_definitions()

        response_1 = self.client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=tools_schema,
            tool_choice="auto"
        )
        
        message_1 = response_1.choices[0].message
        messages.append(message_1)

        if message_1.tool_calls:
            for tool_call in message_1.tool_calls:
                function_name = tool_call.function.name
                arguments = tool_call.function.arguments
                
                logger.info(f"Llamando a herramienta: {function_name} con argumentos: {arguments}")
                
                tool_result = self.registry.execute(function_name, arguments)
                
                messages.append(
                    {
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "name": function_name,
                        "content": tool_result,
                    }
                )
            
            response_2 = self.client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                response_format={"type": "json_object"}
            )
            final_message = response_2.choices[0].message.content
        else:
            final_message = message_1.content

        logger.info("Respuesta final recibida del LLM")
        try:
            if not final_message:
                raise ValueError("Respuesta vacía del LLM")
            
            clean_content = final_message.replace("```json", "").replace("```", "").strip()
            data = json.loads(clean_content)
            return VulnerabilityAnalysis(**data)
        except (json.JSONDecodeError, ValidationError) as e:
            logger.error(f"Validación fallida: {e}")
            raise ValueError(f"Fallo al validar la salida: {e}")

    def _construct_system_prompt(self) -> str:
        """Construye el prompt del sistema incluyendo el esquema de salida."""
        schema_json = json.dumps(VulnerabilityAnalysis.model_json_schema(), indent=2)
        
        return f"""You are an expert Security Validation Agent, specialized in OWASP Top 10 vulnerabilities (SQLi, SSRF, Command Injection, etc.).
Your goal is to validate static analysis findings (SAST) by analyzing code, tracing data flow, and checking for sinks and sanitizers.

You must use the provided tools to gather evidence. Do not guess.
1. ALWAYS start by reading the code context verification around the source and sink.
2. Check for data flow from source to sink.
3. specific sinks and sanitizers.

Your final output MUST be a JSON object strictly adhering to the following schema:
{schema_json}

IMPORTANT:
- The JSON keys must remain in English (as per schema).
- The string values for 'justification', 'explanation', 'assumptions', and 'counterexample' MUST BE IN SPANISH.

If the vulnerability is a True Positive, you must provide a proof of concept trace.
If it is a False Positive, you must explain why (e.g., sanitizer found, broken flow) and provide a counterexample if possible.
"""

    def _construct_user_prompt(
        self,
        vulnerability_id: str,
        file_path: str,
        vulnerability_type: str,
        source_line: int,
        sink_line: int,
        message: str,
    ) -> str:
        """Construye el prompt del usuario con los detalles de la vulnerabilidad."""
        return f"""Analyze this vulnerability:
ID: {vulnerability_id}
Type: {vulnerability_type}
Message: {message}
File: {file_path}
Source Line: {source_line}
Sink Line: {sink_line}
"""

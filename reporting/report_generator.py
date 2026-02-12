import json
from abc import ABC, abstractmethod
from typing import List, Union
from agent.schemas import VulnerabilityAnalysis

class Reporter(ABC):
    """
    Clase base abstracta para generadores de reportes.
    """
    from typing import List, Union

    @abstractmethod
    def generate_report(self, analysis: Union[VulnerabilityAnalysis, List[VulnerabilityAnalysis]], output_path: str):
        """Genera un reporte a partir del análisis y lo guarda en la ruta especificada."""
        pass

class JSONReporter(Reporter):
    """
    Generador de reportes en formato JSON.
    """
    def generate_report(self, analysis: Union[VulnerabilityAnalysis, List[VulnerabilityAnalysis]], output_path: str):
        """Escribe el reporte en formato JSON."""
        with open(output_path, "w", encoding="utf-8") as f:
            if isinstance(analysis, list):
                f.write(json.dumps([a.model_dump() for a in analysis], indent=2))
            else:
                f.write(analysis.model_dump_json(indent=2))

class HTMLReporter(Reporter):
    """
    Generador de reportes en formato HTML.
    """
    def generate_report(self, analysis: Union[VulnerabilityAnalysis, List[VulnerabilityAnalysis]], output_path: str):
        """Genera y guarda un reporte HTML estilizado."""
        
        items = analysis if isinstance(analysis, list) else [analysis]

        rows_html = ""
        for item in items:
            rows_html += f"""
            <div class="header">
                <h2>{item.id} <span style="font-size:0.6em; color:#666">source:{item.trace.source_line} -> sink:{item.trace.sink_line}</span></h2>
                <p><strong>Clasificación:</strong> {item.classification} | <strong>Severidad:</strong> <span class="{item.severity.lower()}">{item.severity}</span></p>
            </div>
            <div class="section">
                <h3>Justificación</h3>
                <p>{item.justification}</p>
                
                <h3>Traza</h3>
                <ul>
                     <li><strong>Flujo:</strong> {', '.join(item.trace.flow)}</li>
                </ul>

                <h3>Sanitizers/Validadores</h3>
                <ul>
                    {(''.join([f'<li>{s.name} (Línea {s.line})</li>' for s in item.sanitizers]) if item.sanitizers else '<li>No detectados</li>')}
                </ul>

                {f'<h3>Contraejemplo</h3><p>{item.counterexample}</p>' if item.counterexample else ''}
                
                <h3>Supuestos</h3>
                <ul>
                    {''.join([f'<li>{a}</li>' for a in item.assumptions])}
                </ul>
                <hr>
            </div>
            """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reporte Consolidado AI Triage</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max_width: 900px; margin: auto; }}
                .header {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; margin-top:30px; }}
                .section {{ margin-left: 10px; }}
                .critical {{ color: red; font-weight:bold; }}
                .high {{ color: orange; font-weight:bold; }}
                .medium {{ color: #b8860b; font-weight:bold; }}
                .low {{ color: green; font-weight:bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Reporte de Vulnerabilidades</h1>
                <p>Total analizado: {len(items)}</p>
                {rows_html}
            </div>
        </body>
        </html>
        """
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

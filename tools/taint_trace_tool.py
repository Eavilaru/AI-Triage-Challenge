from pydantic import BaseModel, Field
from typing import List
import ast
import textwrap
from typing import Set, Dict, Any


class TaintTraceInput(BaseModel):
    snippet: str = Field(..., description="Bloque de código a analizar")
    source_line: int = Field(..., description="Línea del source")
    sink_line: int = Field(..., description="Línea del sink")


class TaintTraceOutput(BaseModel):
    data_flow_detected: bool
    flow_variables: List[str]
    explanation: str


class DependencyTracker(ast.NodeVisitor):
    """
    Visitante de AST para rastrear dependencias de variables dentro de un bloque de código.
    """
    def __init__(self, source_line: int, sink_line: int):
        self.source_line = source_line
        self.sink_line = sink_line
        self.dependencies: Dict[str, Set[str]] = {}
        self.tainted_seeds: Set[str] = set()
        self.sink_candidates: Set[str] = set()

    def _get_vars(self, node: ast.AST) -> Set[str]:
        """Extrae nombres de variables de un nodo."""
        vars_found = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                vars_found.add(child.id)
        return vars_found

    def visit_Assign(self, node: ast.Assign):
        """Rastrea asignaciones para construir el grafo de dependencias."""
        rhs_vars = self._get_vars(node.value)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if var_name not in self.dependencies:
                    self.dependencies[var_name] = set()
                self.dependencies[var_name].update(rhs_vars)
                
                if node.lineno == self.source_line:
                    self.tainted_seeds.add(var_name)
                    
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Identifica variables usadas en llamadas a función en la línea del sink."""
        if node.lineno == self.sink_line:
            for arg in node.args:
                self.sink_candidates.update(self._get_vars(arg))
            for keyword in node.keywords:
                self.sink_candidates.update(self._get_vars(keyword.value))
        
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visita la definición de función."""
        self.generic_visit(node)


def taint_trace_tool(input_data: TaintTraceInput) -> TaintTraceOutput:
    """
    Herramienta de análisis de flujo de Taint utilizando AST.
    """
    cleaned_snippet = textwrap.dedent(input_data.snippet)
    
    try:
        tree = ast.parse(cleaned_snippet)
    except SyntaxError:
        return TaintTraceOutput(
            data_flow_detected=False,
            flow_variables=[],
            explanation="Error de sintaxis al parsear el snippet. Asegúrate de que es código Python válido."
        )

    tracker = DependencyTracker(input_data.source_line, input_data.sink_line)
    tracker.visit(tree)
    
    reachable_flow = []
    data_flow_detected = False
    
    graph = tracker.dependencies
    
    def get_tainted_deps(var_name, visited=None):
        if visited is None: visited = set()
        if var_name in visited: return set()
        visited.add(var_name)
        
        deps = set()
        if var_name in graph:
            for dep in graph[var_name]:
                deps.add(dep)
                deps.update(get_tainted_deps(dep, visited))
        return deps

    matched_vars = []
    
    for sink_var in tracker.sink_candidates:
        all_deps = get_tainted_deps(sink_var)
        intersection = all_deps.intersection(tracker.tainted_seeds)
        
        if sink_var in tracker.tainted_seeds:
            intersection.add(sink_var)
            
        if intersection:
            data_flow_detected = True
            matched_vars.append(f"{sink_var} (depende de {intersection})")
            
    explanation = ""
    if data_flow_detected:
        explanation = f"Flujo detectado: Variables en sink {list(tracker.sink_candidates)} dependen de source {list(tracker.tainted_seeds)}. Cadena: {matched_vars}"
    else:
        if not tracker.tainted_seeds:
             explanation = f"No se identificaron variables taint en la línea {input_data.source_line}. (Posible mismatch de líneas o sintaxis)"
        elif not tracker.sink_candidates:
             explanation = f"No se identificaron sinks en la línea {input_data.sink_line}."
        else:
             explanation = f"No hay flujo de datos entre source {list(tracker.tainted_seeds)} y sink {list(tracker.sink_candidates)}."

    return TaintTraceOutput(
        data_flow_detected=data_flow_detected,
        flow_variables=list(graph.keys()),
        explanation=explanation
    )

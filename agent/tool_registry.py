import json
from typing import Any, Callable, Dict, List, Type
from pydantic import BaseModel

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Callable] = {}
        self._schemas: List[Dict[str, Any]] = []

        return self._schemas

    def get_tool_functions(self) -> List[Callable]:
        return list(self._tools.values())

    def register(self, name: str, func: Callable, input_model: Type[BaseModel]):
        """
        Registra una herramienta y la convierte a FunctionDeclaration de Gemini.
        """
        self._tools[name] = func
        self._models[name] = input_model  # Store model for execution

        # Generate OpenAI tool definition from Pydantic model
        schema = input_model.model_json_schema()
        
        tool_def = {
            "type": "function",
            "function": {
                "name": name,
                "description": schema.get("description", "") or f"Tool {name}",
                "parameters": {
                    "type": "object",
                    "properties": schema.get("properties", {}),
                    "required": schema.get("required", []),
                },
            },
        }
        self._schemas.append(tool_def)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        return self._schemas


    def get_tool_functions(self) -> List[Callable]:
        return list(self._tools.values())

    def execute(self, name: str, arguments_json: str) -> str:
        if name not in self._tools:
            return f"Error: Tool '{name}' not found."
        
        try:
            # Parse arguments
            args = json.loads(arguments_json)
            # Find the input model from the registered tool? 
            # Ideally we'd store the model too, but for now we assume the tool handles dict or we need to wrap it.
            # actually, the existing tools take a Pydantic model as input.
            # So we need to handle that instantiation.
            
            # Let's adjust register to store the model too.
            pass 
        except Exception as e:
            return f"Error executing tool '{name}': {str(e)}"
        
        return "Not implemented yet"

class SmartToolRegistry(ToolRegistry):
    def __init__(self):
        super().__init__()
        self._models: Dict[str, Type[BaseModel]] = {}

    def register(self, name: str, func: Callable, input_model: Type[BaseModel]):
        # Call parent register which now handles logic
        super().register(name, func, input_model)

    def execute(self, name: str, arguments_json: str) -> str:
        if name not in self._tools:
            return f"Error: Tool '{name}' not found."
        
        try:
            args_dict = json.loads(arguments_json)
            model_class = self._models[name]
            input_data = model_class(**args_dict)
            
            result = self._tools[name](input_data)
            
            # If result is a Pydantic model, dump to JSON
            if isinstance(result, BaseModel):
                return result.model_dump_json()
            return str(result)
            
        except json.JSONDecodeError:
            return "Error: Invalid JSON arguments."
        except Exception as e:
            return f"Error executing tool '{name}': {str(e)}"

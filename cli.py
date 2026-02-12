import argparse
import json
import sys
import os
from agent.security_agent import SecurityValidationAgent
from reporting.report_generator import JSONReporter, HTMLReporter

def main():
    """
    Función principal del CLI para orquestar la validación de vulnerabilidades.
    """
    parser = argparse.ArgumentParser(description="AI Triage CLI - Validación de Análisis Estático")
    parser.add_argument("file", help="Ruta al archivo JSON de vulnerabilidad")
    parser.add_argument("--source", help="Ruta al archivo fuente Python a analizar", required=True)
    parser.add_argument("--api-key", help="Clave API de OpenAI (opcional, o configurar variable de entorno OPENAI_API_KEY)")
    parser.add_argument("--output", help="Ruta para guardar el reporte de salida (JSON)", default="report.json")
    
    args = parser.parse_args()
    
    # Cargar variables de entorno desde .env manualmente para evitar dependencias extra
    if os.path.exists(".env"):
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip().strip('"').strip("'")

    if not os.path.exists(args.file):
        print(f"Error: Archivo de hallazgos '{args.file}' no encontrado.")
        sys.exit(1)

    if not os.path.exists(args.source):
        print(f"Error: Archivo fuente '{args.source}' no encontrado.")
        sys.exit(1)
        
    try:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Archivo no encontrado: {args.file}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Archivo JSON inválido: {args.file}")
        sys.exit(1)

    if isinstance(data, list):
        vulnerabilities = data
    elif "vulnerabilities" in data:
        vulnerabilities = data["vulnerabilities"]
    else:
        vulnerabilities = [data]

    if args.output.endswith(".html"):
        reporter = HTMLReporter()
    else:
        reporter = JSONReporter()

    agent = SecurityValidationAgent(api_key=args.api_key)
    results = []

    print(f"Se encontraron {len(vulnerabilities)} hallazgos para analizar sobre '{args.source}'.\n")

    for i, vuln in enumerate(vulnerabilities):
        vuln_id = vuln.get("id", f"VULN-{i+1}")
        print(f"[{i+1}/{len(vulnerabilities)}] Analizando {vuln_id} ({vuln.get('type') or vuln.get('vulnerability_type')})...")
        
        # Usar siempre el archivo fuente proporcionado por CLI
        file_path = args.source


        try:
            analysis = agent.analyze_vulnerability(
                vulnerability_id=vuln_id,
                file_path=file_path,
                vulnerability_type=vuln.get("type") or vuln.get("vulnerability_type"),
                source_line=vuln.get("source_line"),
                sink_line=vuln.get("sink_line"),
                message=vuln.get("message"),
            )
            results.append(analysis)
            print("  Ok.")
        except Exception as e:
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()

    if results:
        base_output = os.path.splitext(args.output)[0]
        json_output = f"{base_output}.json"
        
        json_reporter = JSONReporter()
        json_reporter.generate_report(results, json_output)
        print(f"\nReporte JSON generado en: {json_output}")

        if args.output.endswith(".html"):
            html_reporter = HTMLReporter()
            html_reporter.generate_report(results, args.output)
            print(f"Reporte HTML generado en: {args.output}")
    else:
        print("\nNo se generaron resultados exitosos.")

if __name__ == "__main__":
    main()

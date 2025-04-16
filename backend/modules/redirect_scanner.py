#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

logger = logging.getLogger("nsf.redirect_scanner")

# User-Agent para requisições
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Domínios externos para teste de redirecionamento
# Domínios externos para teste de redirecionamento
EXTERNAL_DOMAINS = [
    "https://example.com",
    "https://evil.com",
    "https://attacker.com",
    "https://google.com",
    "https://facebook.com"
]

# Payloads para Open Redirect
REDIRECT_PAYLOADS = [
    "{domain}",
    "https://{domain}",
    "https://{domain}/path",
    "//{domain}",
    "//{domain}/path",
    "/{domain}",
    "https://sub.{domain}",
    "https%3A%2F%2F{domain}",
    "%2F%2F{domain}",
    "{domain}%252F%252F",
    "%252F%252F{domain}",
    "/redirect?url={domain}",
    "/redirect?uri={domain}",
    "/redirect?path={domain}",
    "/redirect?target={domain}",
    "/redirect?to={domain}",
    "{domain}\\@example.com",
    "\\{domain}"
]

def scan_redirect(target, params=None):
    """
    Escaneia um site em busca de vulnerabilidades de Open Redirect.
    
    Args:
        target (str): URL alvo (ex: https://exemplo.com)
        params (list): Lista de parâmetros a serem testados. Se None, será feita uma detecção automática.
    
    Returns:
        dict: Resultado do scan com vulnerabilidades encontradas
    """
    logger.info(f"Iniciando scan de Open Redirect em {target}")
    
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
    
    # Se nenhuma lista de parâmetros fornecida, tentar descobrir automaticamente
    if not params:
        params = discover_redirect_parameters(target, headers)
    
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
    
    # Filtragem adicional para parâmetros com nomes suspeitos
    redirect_params = []
    suspicious_param_names = ['redirect', 'url', 'link', 'goto', 'target', 'path', 'uri', 'return', 'src', 'dest', 'destination', 'redir', 'redirect_uri', 'next', 'continue']
    
    for test in unique_tests:
        param = test['param'].lower()
        # Priorizar parâmetros com nomes suspeitos
        if any(susp in param for susp in suspicious_param_names):
            redirect_params.append(test)
    
    # Se não encontrar parâmetros suspeitos, usar todos os parâmetros
    if not redirect_params:
        redirect_params = unique_tests
    
    # Resultados
    vulnerabilities = []
    
    # Função para testar um único payload
    def test_payload(test, payload):
        url = test['url']
        method = test['method']
        param = test['param']
        param_type = test.get('type', 'url')
        
        # Escolher um domínio de teste
        for domain in EXTERNAL_DOMAINS:
            # Formatar o payload com o domínio
            formatted_payload = payload.format(domain=domain.replace('https://', '').replace('http://', ''))
            
            try:
                if method == 'GET':
                    # Construir URL com o payload
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [formatted_payload]
                    new_query = urlencode(query_params, doseq=True)
                    test_url = parsed_url._replace(query=new_query).geturl()
                    
                    response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
                else:  # POST
                    data = {param: formatted_payload}
                    response = requests.post(url, headers=headers, data=data, timeout=10, allow_redirects=False)
                
                # Verificar se ocorreu um redirecionamento
                location = response.headers.get('Location', '')
                
                # Verificar se o redirecionamento é para o domínio externo
                domain_without_scheme = domain.replace('https://', '').replace('http://', '')
                
                if (response.status_code in [301, 302, 303, 307, 308] and 
                    (domain in location or domain_without_scheme in location)):
                    return {
                        'url': url,
                        'method': method,
                        'param': param,
                        'payload': formatted_payload,
                        'redirect_url': location,
                        'status_code': response.status_code,
                        'vulnerable': True,
                        'details': f"Redirecionamento para domínio externo: {location}"
                    }
                
                # Verificar também se o domínio está presente na resposta como um redirecionamento por JavaScript
                if response.status_code == 200:
                    js_redirect_patterns = [
                        f"window.location.*=.*['\"]https?://{re.escape(domain_without_scheme)}",
                        f"window.location.*=.*['\"].*{re.escape(domain_without_scheme)}",
                        f"location.href.*=.*['\"]https?://{re.escape(domain_without_scheme)}",
                        f"location.href.*=.*['\"].*{re.escape(domain_without_scheme)}",
                        f"top.location.*=.*['\"]https?://{re.escape(domain_without_scheme)}",
                        f"document.location.*=.*['\"]https?://{re.escape(domain_without_scheme)}"
                    ]
                    
                    for pattern in js_redirect_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            return {
                                'url': url,
                                'method': method,
                                'param': param,
                                'payload': formatted_payload,
                                'redirect_url': f"JavaScript redirect to {domain}",
                                'status_code': response.status_code,
                                'vulnerable': True,
                                'details': f"Redirecionamento JavaScript para domínio externo"
                            }
            
            except Exception as e:
                logger.debug(f"Erro ao testar payload {formatted_payload} em {url}, parâmetro {param}: {str(e)}")
        
        return None
    
    # Testar todos os payloads em todos os parâmetros
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        
        for test in redirect_params:
            for payload in REDIRECT_PAYLOADS:
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
                    logger.info(f"Vulnerabilidade Open Redirect encontrada: {result['url']}, parâmetro {result['param']}")
    
    return {
        'vulnerabilities': vulnerabilities,
        'tested_parameters': len(redirect_params),
        'tested_payloads': len(REDIRECT_PAYLOADS) * len(EXTERNAL_DOMAINS),
        'vulnerable_count': len(vulnerabilities),
        'target': target
    }

def discover_redirect_parameters(target, headers):
    """
    Descobre parâmetros que podem ser usados para redirecionamento.
    
    Args:
        target (str): URL alvo
        headers (dict): Headers para requisição
    
    Returns:
        list: Lista de parâmetros potencialmente vulneráveis
    """
    discovered_params = []
    suspicious_param_names = ['redirect', 'url', 'link', 'goto', 'target', 'path', 'uri', 'return', 'src', 'dest', 'destination', 'redir', 'redirect_uri', 'next', 'continue']
    
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
                    # Priorizar parâmetros com nomes suspeitos
                    if any(susp in input_name.lower() for susp in suspicious_param_names):
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
                    # Priorizar parâmetros com nomes suspeitos
                    if any(susp in param.lower() for susp in suspicious_param_names):
                        discovered_params.append({
                            'url': link_url,
                            'method': 'GET',
                            'param': param,
                            'type': 'url'
                        })
        
        # Se não encontramos parâmetros suspeitos, verificar todos os parâmetros
        if not discovered_params:
            # Parâmetros de URL atual
            parsed_url = urlparse(target)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                for param in query_params.keys():
                    discovered_params.append({
                        'url': target,
                        'method': 'GET',
                        'param': param,
                        'type': 'url'
                    })
    
    except Exception as e:
        logger.error(f"Erro ao descobrir parâmetros de redirecionamento: {str(e)}")
    
    return discovered_params
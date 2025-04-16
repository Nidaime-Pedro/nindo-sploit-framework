#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse

logger = logging.getLogger("nsf.tech_scanner")

# User-Agent para requisições
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Dicionário de tecnologias com padrões a serem encontrados
TECHNOLOGIES = {
    'WordPress': {
        'patterns': [
            '<meta name="generator" content="WordPress',
            '/wp-content/',
            '/wp-includes/',
            'wp-json/'
        ],
        'headers': {
            'X-Powered-By': 'WordPress'
        },
        'cookies': ['wordpress_', 'wp-settings-'],
        'category': 'CMS'
    },
    'Joomla': {
        'patterns': [
            '<meta name="generator" content="Joomla',
            '/media/jui/',
            '/media/system/js/core.js'
        ],
        'cookies': ['joomla_user_state'],
        'category': 'CMS'
    },
    'Drupal': {
        'patterns': [
            '<meta name="Generator" content="Drupal',
            'jQuery.extend(Drupal.settings',
            'Drupal.settings',
            'drupal.js'
        ],
        'headers': {
            'X-Generator': 'Drupal'
        },
        'cookies': ['Drupal.visitor'],
        'category': 'CMS'
    },
    'Bootstrap': {
        'patterns': [
            'bootstrap.min.css',
            'bootstrap.min.js',
            'class="container"',
            'class="navbar'
        ],
        'category': 'UI Framework'
    },
    'jQuery': {
        'patterns': [
            'jquery.min.js',
            'jquery.js',
            'jQuery('
        ],
        'category': 'JavaScript Library'
    },
    'React': {
        'patterns': [
            'react.js',
            'react.min.js',
            'react-dom.js',
            'react-dom.min.js',
            '_reactRootContainer'
        ],
        'category': 'JavaScript Framework'
    },
    'Vue.js': {
        'patterns': [
            'vue.js',
            'vue.min.js',
            'data-v-',
            '__vue__'
        ],
        'category': 'JavaScript Framework'
    },
    'Angular': {
        'patterns': [
            'ng-app',
            'ng-controller',
            'angular.min.js',
            'angular.js',
            'ng-model'
        ],
        'category': 'JavaScript Framework'
    },
    'PHP': {
        'headers': {
            'X-Powered-By': 'PHP'
        },
        'cookies': ['PHPSESSID'],
        'category': 'Programming Language'
    },
    'ASP.NET': {
        'headers': {
            'X-Powered-By': 'ASP.NET',
            'X-AspNet-Version': '.*'
        },
        'cookies': ['ASP.NET_SessionId'],
        'category': 'Web Framework'
    },
    'Laravel': {
        'cookies': ['laravel_session'],
        'headers': {
            'X-XSRF-TOKEN': '.*'
        },
        'category': 'Web Framework'
    },
    'Django': {
        'patterns': [
            'csrfmiddlewaretoken',
            '__admin_media_prefix__'
        ],
        'cookies': ['django_', 'csrftoken'],
        'category': 'Web Framework'
    },
    'Express.js': {
        'headers': {
            'X-Powered-By': 'Express'
        },
        'category': 'Web Framework'
    },
    'Google Analytics': {
        'patterns': [
            'google-analytics.com/analytics.js',
            'ga\\(\'create\'',
            'gtag\\('
        ],
        'category': 'Analytics'
    },
    'Cloudflare': {
        'headers': {
            'Server': 'cloudflare',
            'CF-RAY': '.*'
        },
        'cookies': ['__cfduid', '__cf_bm'],
        'category': 'CDN/Security'
    },
    'Nginx': {
        'headers': {
            'Server': 'nginx'
        },
        'category': 'Web Server'
    },
    'Apache': {
        'headers': {
            'Server': 'Apache'
        },
        'category': 'Web Server'
    },
    'IIS': {
        'headers': {
            'Server': 'Microsoft-IIS'
        },
        'category': 'Web Server'
    }
}

def scan_technologies(target):
    """
    Escaneia um site para detectar tecnologias utilizadas.
    
    Args:
        target (str): URL alvo (ex: https://exemplo.com)
    
    Returns:
        dict: Resultado do scan com tecnologias detectadas
    """
    logger.info(f"Iniciando scan de tecnologias em {target}")
    
    # Normalizar URL alvo
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Headers para requisições
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    
    detected_technologies = []
    javascript_libraries = []
    
    try:
        # Fazer a requisição
        response = requests.get(target, headers=headers, timeout=10)
        html_content = response.text
        response_headers = response.headers
        cookies = response.cookies
        
        # Analisar o conteúdo HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Verificar cada tecnologia
        for tech_name, tech_info in TECHNOLOGIES.items():
            version = None
            confidence = 0
            evidence = []
            
            # Verificar padrões no HTML
            if 'patterns' in tech_info:
                for pattern in tech_info['patterns']:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        confidence += 25  # Aumentar confiança
                        evidence.append(f"Padrão encontrado: {pattern}")
                        
                        # Tentar encontrar versão
                        if not version:
                            version = extract_version(tech_name, pattern, html_content, soup)
            
            # Verificar headers
            if 'headers' in tech_info:
                for header_name, header_pattern in tech_info['headers'].items():
                    if header_name in response_headers:
                        header_value = response_headers[header_name]
                        if re.search(header_pattern, header_value, re.IGNORECASE):
                            confidence += 30
                            evidence.append(f"Header encontrado: {header_name}: {header_value}")
                            
                            # Extrair versão de headers
                            if not version and 'PHP' in tech_name and 'PHP' in header_value:
                                version_match = re.search(r'PHP/([0-9\.]+)', header_value)
                                if version_match:
                                    version = version_match.group(1)
                            elif not version and 'ASP.NET' in tech_name and header_name == 'X-AspNet-Version':
                                version = header_value
            
            # Verificar cookies
            if 'cookies' in tech_info:
                for cookie_pattern in tech_info['cookies']:
                    for cookie in cookies:
                        if re.search(cookie_pattern, cookie.name, re.IGNORECASE):
                            confidence += 20
                            evidence.append(f"Cookie encontrado: {cookie.name}")
            
            # Se confiança > 0, adicionar à lista de tecnologias detectadas
            if confidence > 0:
                tech = {
                    'name': tech_name,
                    'category': tech_info.get('category', 'Other'),
                    'confidence': min(confidence, 100),  # Máximo 100%
                    'version': version,
                    'evidence': evidence
                }
                detected_technologies.append(tech)
        
        # Detectar bibliotecas JavaScript
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src']
            # Analisar o nome do arquivo para identificar bibliotecas
            js_file = src.split('/')[-1]
            
            # Verificar versões de bibliotecas comuns
            version_match = re.search(r'([a-zA-Z0-9\.-]+)\.min\.js', js_file)
            if version_match:
                lib_name = version_match.group(1)
                if '.' in lib_name:
                    # Pode conter versão (ex: jquery-3.6.0)
                    parts = lib_name.split('-')
                    if len(parts) > 1 and re.match(r'^[0-9\.]+$', parts[-1]):
                        actual_lib = '-'.join(parts[:-1])
                        version = parts[-1]
                        javascript_libraries.append({
                            'name': actual_lib,
                            'version': version,
                            'url': src
                        })
                    else:
                        javascript_libraries.append({
                            'name': lib_name,
                            'url': src
                        })
        
        # Analisar metadados (generator, etc)
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            content = generator.get('content')
            for tech_name in TECHNOLOGIES:
                if tech_name.lower() in content.lower():
                    # Verificar se já detectamos esta tecnologia
                    already_detected = False
                    for tech in detected_technologies:
                        if tech['name'] == tech_name:
                            already_detected = True
                            # Atualizar confiança e evidência
                            tech['confidence'] = min(tech['confidence'] + 30, 100)
                            tech['evidence'].append(f"Meta generator: {content}")
                            # Extrair versão se não tiver
                            if not tech['version']:
                                version_match = re.search(r'(\d+\.\d+(\.\d+)?)', content)
                                if version_match:
                                    tech['version'] = version_match.group(1)
                            break
                    
                    if not already_detected:
                        # Extrair versão
                        version = None
                        version_match = re.search(r'(\d+\.\d+(\.\d+)?)', content)
                        if version_match:
                            version = version_match.group(1)
                        
                        detected_technologies.append({
                            'name': tech_name,
                            'category': TECHNOLOGIES[tech_name].get('category', 'Other'),
                            'confidence': 80,  # Alta confiança para meta generator
                            'version': version,
                            'evidence': [f"Meta generator: {content}"]
                        })
        
        # Ordenar tecnologias por confiança (decrescente)
        detected_technologies.sort(key=lambda x: x['confidence'], reverse=True)
        
        return {
            'technologies': detected_technologies,
            'javascript_libraries': javascript_libraries,
            'url': target,
            'status': response.status_code,
            'server': response_headers.get('Server', 'Unknown')
        }
    
    except Exception as e:
        logger.error(f"Erro ao escanear tecnologias: {str(e)}")
        raise
        
def extract_version(tech_name, pattern, html_content, soup):
    """Tenta extrair a versão de uma tecnologia."""
    version = None
    
    # Buscar versão no caso de WordPress
    if tech_name == 'WordPress' and pattern == '<meta name="generator" content="WordPress':
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            content = generator.get('content')
            version_match = re.search(r'WordPress ([0-9\.]+)', content)
            if version_match:
                version = version_match.group(1)
    
    # jQuery versão
    elif tech_name == 'jQuery' and ('jquery.min.js' in pattern or 'jquery.js' in pattern):
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src']
            if 'jquery' in src.lower():
                version_match = re.search(r'jquery-([0-9\.]+)', src.lower())
                if version_match:
                    version = version_match.group(1)
                    break
    
    # Bootstrap versão
    elif tech_name == 'Bootstrap' and 'bootstrap.min.css' in pattern:
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            href = link.get('href', '')
            if 'bootstrap' in href.lower():
                version_match = re.search(r'bootstrap[.-]([0-9\.]+)', href.lower())
                if version_match:
                    version = version_match.group(1)
                    break
    
    return version
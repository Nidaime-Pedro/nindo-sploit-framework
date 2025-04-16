#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("nsf.plugin_scanner")

# User-Agent para requisições
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Plugins comuns para verificar (apenas uma pequena amostra para cada CMS)
CMS_PLUGINS = {
    'wordpress': [
        'contact-form-7', 'woocommerce', 'yoast-seo', 'akismet', 'jetpack',
        'wordfence', 'elementor', 'gutenberg', 'classic-editor', 'wpforms-lite',
        'wp-super-cache', 'w3-total-cache', 'all-in-one-seo-pack', 'duplicator',
        'redirection', 'google-analytics-for-wordpress', 'google-sitemap-generator',
        'wp-mail-smtp', 'bbpress', 'tinymce-advanced', 'advanced-custom-fields'
    ],
    'joomla': [
        'content', 'system', 'user', 'search', 'authentication', 'editors',
        'editors-xtd', 'finder', 'extension', 'categories', 'installer',
        'quick-icons', 'twofactorauth', 'actionlog', 'fields'
    ],
    'drupal': [
        'views', 'token', 'ctools', 'pathauto', 'metatag', 'admin_toolbar',
        'webform', 'devel', 'google_analytics', 'entity', 'paragraphs',
        'field_group', 'colorbox', 'xmlsitemap', 'captcha', 'redirect'
    ]
}

# Endpoints para detecção de plugins
CMS_ENDPOINTS = {
    'wordpress': {
        'plugins': '/wp-content/plugins/',
        'themes': '/wp-content/themes/',
        'readme': 'readme.txt',
        'plugin_api': '/wp-json/wp/v2/plugins'
    },
    'joomla': {
        'plugins': '/plugins/',
        'templates': '/templates/',
        'components': '/components/',
        'modules': '/modules/'
    },
    'drupal': {
        'modules': '/modules/',
        'themes': '/themes/',
        'sites_modules': '/sites/all/modules/',
        'sites_themes': '/sites/all/themes/'
    }
}

# Marcadores para detecção de versão
VERSION_MARKERS = {
    'wordpress': {
        'plugin': [
            r'Version:\s*([0-9\.]+)',
            r'Stable tag:\s*([0-9\.]+)'
        ],
        'theme': [
            r'Version:\s*([0-9\.]+)'
        ]
    },
    'joomla': {
        'plugin': [
            r'<version>([0-9\.]+)</version>',
            r'version="([0-9\.]+)"'
        ]
    },
    'drupal': {
        'module': [
            r'version\s*=\s*"([0-9\.]+)"',
            r"version\s*=\s*'([0-9\.]+)'"
        ]
    }
}

def scan_plugins(target, cms='wordpress'):
    """
    Escaneia plugins e temas de CMS em um site.
    
    Args:
        target (str): URL alvo (ex: https://exemplo.com)
        cms (str): Sistema de gerenciamento de conteúdo ('wordpress', 'joomla', 'drupal')
    
    Returns:
        dict: Resultado do scan com plugins detectados
    """
    logger.info(f"Iniciando scan de plugins {cms} em {target}")
    
    # Normalizar URL alvo
    if not target.endswith('/'):
        target += '/'
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Validar o CMS
    cms = cms.lower()
    if cms not in CMS_PLUGINS:
        logger.error(f"CMS não suportado: {cms}")
        raise ValueError(f"CMS não suportado: {cms}. Suportados: {', '.join(CMS_PLUGINS.keys())}")
    
    # Headers para requisições
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    
    # Primeiro, confirmar se o site realmente usa o CMS especificado
    cms_detected = detect_cms(target, headers)
    if cms_detected != cms:
        logger.warning(f"CMS especificado ({cms}) não corresponde ao detectado ({cms_detected})")
    
    # Lista de plugins a serem verificados
    plugins_to_check = CMS_PLUGINS[cms]
    
    # Resultados
    detected_plugins = []
    
    # Funções específicas para cada CMS
    if cms == 'wordpress':
        detected_plugins = scan_wordpress_plugins(target, plugins_to_check, headers)
    elif cms == 'joomla':
        detected_plugins = scan_joomla_extensions(target, plugins_to_check, headers)
    elif cms == 'drupal':
        detected_plugins = scan_drupal_modules(target, plugins_to_check, headers)
    
    # Ordenar plugins por nome
    detected_plugins.sort(key=lambda x: x['name'])
    
    # Verificar plugins com vulnerabilidades conhecidas
    for plugin in detected_plugins:
        if plugin.get('version'):
            # Simular verificação de vulnerabilidades
            plugin['vulnerabilities'] = check_plugin_vulnerabilities(cms, plugin['name'], plugin['version'])
    
    return {
        'plugins': detected_plugins,
        'total': len(detected_plugins),
        'cms': cms,
        'target': target
    }

def detect_cms(target, headers):
    """
    Detecta qual CMS o site está usando.
    
    Args:
        target (str): URL alvo
        headers (dict): Headers para requisição
    
    Returns:
        str: CMS detectado ('wordpress', 'joomla', 'drupal', ou 'unknown')
    """
    try:
        response = requests.get(target, headers=headers, timeout=10)
        html_content = response.text
        
        # Verificar WordPress
        wp_patterns = [
            '/wp-content/', 
            '<meta name="generator" content="WordPress',
            'wp-includes',
            'wp-login.php'
        ]
        for pattern in wp_patterns:
            if pattern in html_content:
                return 'wordpress'
        
        # Verificar Joomla
        joomla_patterns = [
            '<meta name="generator" content="Joomla',
            '/media/jui/',
            'Joomla!'
        ]
        for pattern in joomla_patterns:
            if pattern in html_content:
                return 'joomla'
        
        # Verificar Drupal
        drupal_patterns = [
            'jQuery.extend(Drupal.settings',
            'data-drupal-',
            'Drupal.settings',
            'drupal.js'
        ]
        for pattern in drupal_patterns:
            if pattern in html_content:
                return 'drupal'
        
        # Testar endpoints específicos
        wp_test = requests.get(target + 'wp-login.php', headers=headers, timeout=5)
        if wp_test.status_code == 200 and 'WordPress' in wp_test.text:
            return 'wordpress'
        
        joomla_test = requests.get(target + 'administrator', headers=headers, timeout=5)
        if joomla_test.status_code == 200 and ('Joomla' in joomla_test.text or 'com_' in joomla_test.text):
            return 'joomla'
        
        drupal_test = requests.get(target + 'user/login', headers=headers, timeout=5)
        if drupal_test.status_code == 200 and 'Drupal' in drupal_test.text:
            return 'drupal'
        
        return 'unknown'
    
    except Exception as e:
        logger.error(f"Erro ao detectar CMS: {str(e)}")
        return 'unknown'

def scan_wordpress_plugins(target, plugins_to_check, headers):
    """
    Escaneia plugins WordPress.
    
    Args:
        target (str): URL alvo
        plugins_to_check (list): Lista de plugins para verificar
        headers (dict): Headers para requisição
    
    Returns:
        list: Lista de plugins detectados
    """
    detected_plugins = []
    
    # Função para verificar um único plugin
    def check_plugin(plugin_name):
        plugin_url = urljoin(target, f"wp-content/plugins/{plugin_name}/")
        plugin_readme = urljoin(plugin_url, "readme.txt")
        
        try:
            # Verificar se o diretório do plugin existe
            response = requests.head(plugin_url, headers=headers, timeout=5)
            if response.status_code in [200, 403]:  # 200 OK ou 403 Forbidden (proibido, mas existe)
                # Tentar obter versão do readme.txt
                version = None
                
                try:
                    readme_response = requests.get(plugin_readme, headers=headers, timeout=5)
                    if readme_response.status_code == 200:
                        readme_content = readme_response.text
                        for pattern in VERSION_MARKERS['wordpress']['plugin']:
                            version_match = re.search(pattern, readme_content)
                            if version_match:
                                version = version_match.group(1)
                                break
                except:
                    pass
                
                # Se não encontrou versão no readme, tentar outros métodos
                if not version:
                    try:
                        # Verificar o arquivo principal do plugin
                        main_file_url = urljoin(plugin_url, f"{plugin_name}.php")
                        main_response = requests.get(main_file_url, headers=headers, timeout=5)
                        if main_response.status_code == 200:
                            main_content = main_response.text
                            version_match = re.search(r'Version:\s*([0-9\.]+)', main_content)
                            if version_match:
                                version = version_match.group(1)
                    except:
                        pass
                
                return {
                    'name': plugin_name,
                    'url': plugin_url,
                    'version': version,
                    'status': 'ativo'  # Suposição simplificada
                }
        except Exception as e:
            logger.debug(f"Erro ao verificar plugin {plugin_name}: {str(e)}")
        
        return None
    
    # Verificar temas
    def check_themes():
        themes = []
        theme_url = urljoin(target, "wp-content/themes/")
        
        try:
            response = requests.get(theme_url, headers=headers, timeout=5)
            if response.status_code == 200:
                # Tentar analisar listagem de diretório se disponível
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a')
                
                for link in links:
                    href = link.get('href')
                    if href and href.endswith('/') and not href.startswith('?') and href != '../':
                        theme_name = href.rstrip('/')
                        themes.append(theme_name)
            
            # Se não conseguir detectar pelos diretórios, tentar pelo HTML
            if not themes:
                main_response = requests.get(target, headers=headers, timeout=5)
                if main_response.status_code == 200:
                    html_content = main_response.text
                    theme_match = re.search(r'wp-content/themes/([^/]+)/', html_content)
                    if theme_match:
                        themes.append(theme_match.group(1))
        except Exception as e:
            logger.error(f"Erro ao verificar temas: {str(e)}")
        
        return themes
    
    # Verificar plugins usando threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_plugin, plugin) for plugin in plugins_to_check]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                detected_plugins.append(result)
    
    # Adicionar informações sobre os temas
    themes = check_themes()
    for theme in themes:
        detected_plugins.append({
            'name': theme,
            'url': urljoin(target, f"wp-content/themes/{theme}/"),
            'version': None,
            'status': 'ativo',
            'type': 'theme'
        })
    
    return detected_plugins

def scan_joomla_extensions(target, extensions_to_check, headers):
    """Escaneia extensões do Joomla."""
    detected_extensions = []
    
    # Função para verificar uma única extensão
    def check_extension(extension_name):
        # Em Joomla, verificar componentes, módulos e plugins
        component_url = urljoin(target, f"components/com_{extension_name}/")
        plugin_url = urljoin(target, f"plugins/{extension_name}/")
        module_url = urljoin(target, f"modules/mod_{extension_name}/")
        
        for type_url, prefix, ext_type in [
            (component_url, "com_", "component"),
            (plugin_url, "", "plugin"),
            (module_url, "mod_", "module")
        ]:
            try:
                response = requests.head(type_url, headers=headers, timeout=5)
                if response.status_code in [200, 403]:
                    # Extensão detectada
                    return {
                        'name': f"{prefix}{extension_name}",
                        'url': type_url,
                        'version': None,  # Difícil detectar versão no Joomla
                        'status': 'ativo',  # Suposição simplificada
                        'type': ext_type
                    }
            except:
                pass
        
        return None
    
    # Verificar extensões usando threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_extension, ext) for ext in extensions_to_check]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                detected_extensions.append(result)
    
    return detected_extensions

def scan_drupal_modules(target, modules_to_check, headers):
    """Escaneia módulos do Drupal."""
    detected_modules = []
    
    # Função para verificar um único módulo
    def check_module(module_name):
        # No Drupal, verificar em diferentes locais
        paths = [
            f"modules/{module_name}/",
            f"modules/contrib/{module_name}/",
            f"sites/all/modules/{module_name}/",
            f"sites/default/modules/{module_name}/"
        ]
        
        for path in paths:
            module_url = urljoin(target, path)
            try:
                response = requests.head(module_url, headers=headers, timeout=5)
                if response.status_code in [200, 403]:
                    # Módulo detectado
                    return {
                        'name': module_name,
                        'url': module_url,
                        'version': None,  # Difícil detectar versão no Drupal
                        'status': 'ativo',  # Suposição simplificada
                        'type': 'module'
                    }
            except:
                pass
        
        return None
    
    # Verificar módulos usando threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_module, module) for module in modules_to_check]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                detected_modules.append(result)
    
    return detected_modules

def check_plugin_vulnerabilities(cms, plugin_name, version):
    """
    Verifica se um plugin tem vulnerabilidades conhecidas.
    
    Nota: Esta é uma simulação. Em um ambiente real, este método consultaria
    uma base de dados de vulnerabilidades ou uma API externa.
    
    Args:
        cms (str): CMS do plugin
        plugin_name (str): Nome do plugin
        version (str): Versão do plugin
    
    Returns:
        list: Lista de vulnerabilidades encontradas
    """
    # Simulação de vulnerabilidades conhecidas (apenas para demonstração)
    vulnerable_plugins = {
        'wordpress': {
            'contact-form-7': {
                '5.0.0': [
                    {
                        'id': 'CVE-2018-12641',
                        'title': 'Cross-Site Scripting (XSS)',
                        'description': 'Vulnerabilidade XSS em versões anteriores à 5.0.1'
                    }
                ]
            },
            'wp-super-cache': {
                '1.6.0': [
                    {
                        'id': 'CVE-2019-20041',
                        'title': 'CSRF Vulnerability',
                        'description': 'Vulnerabilidade CSRF em versões anteriores à 1.6.1'
                    }
                ]
            }
        },
        'joomla': {
            'com_content': {
                '3.0.0': [
                    {
                        'id': 'CVE-2018-12345',
                        'title': 'SQL Injection',
                        'description': 'Vulnerabilidade de injeção SQL em versões anteriores à 3.0.1'
                    }
                ]
            }
        },
        'drupal': {
            'views': {
                '7.x-3.23': [
                    {
                        'id': 'CVE-2020-13666',
                        'title': 'Remote Code Execution',
                        'description': 'Vulnerabilidade RCE em versões anteriores à 7.x-3.24'
                    }
                ]
            }
        }
    }
    
    # Verificar se o plugin e versão estão na lista de vulnerabilidades
    vulns = []
    
    if cms in vulnerable_plugins and plugin_name in vulnerable_plugins[cms]:
        for vuln_version, vuln_list in vulnerable_plugins[cms][plugin_name].items():
            # Verificar se a versão atual é vulnerável (simplificado)
            # Em um sistema real, precisaria de comparação semântica de versões
            if version == vuln_version or version < vuln_version:
                vulns.extend(vuln_list)
    
    return vulns
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger("nsf.subdomain_scanner")

def scan_subdomains(target, method='bruteforce'):
    """
    Escaneia subdomínios de um domínio alvo.
    
    Args:
        target (str): Domínio alvo (ex: exemplo.com)
        method (str): Método de scan ('bruteforce' ou 'passive')
        
    Returns:
        dict: Resultados do scan com subdomínios encontrados
    """
    logger.info(f"Iniciando scan de subdomínios em {target} (método: {method})")
    
    # Remover http:// ou https:// se presente
    if target.startswith('http://'):
        target = target[7:]
    elif target.startswith('https://'):
        target = target[8:]
    
    # Remover caminho após domínio
    target = target.split('/', 1)[0]
    
    # Remover subdomínios existentes para obter apenas o domínio principal
    parts = target.split('.')
    if len(parts) > 2:
        target = '.'.join(parts[-2:])
    
    discovered_subdomains = []
    
    try:
        if method == 'passive':
            discovered_subdomains = passive_subdomain_scan(target)
        else:  # método padrão: bruteforce
            discovered_subdomains = bruteforce_subdomain_scan(target)
        
        # Verificar se cada subdomínio está ativo
        validated_subdomains = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            
            for subdomain in discovered_subdomains:
                futures.append(
                    executor.submit(validate_subdomain, subdomain)
                )
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    validated_subdomains.append(result)
        
        return {
            'subdomains': validated_subdomains,
            'total': len(validated_subdomains),
            'target': target,
        }
    
    except Exception as e:
        logger.error(f"Erro ao escanear subdomínios: {str(e)}")
        raise
        
def bruteforce_subdomain_scan(domain):
    """
    Realiza scan de subdomínios por força bruta.
    
    Args:
        domain (str): Domínio a ser escaneado
        
    Returns:
        list: Lista de subdomínios encontrados
    """
    logger.info(f"Realizando scan de subdomínios por força bruta em {domain}")
    
    # Lista comum de subdomínios para testar
    common_subdomains = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 
        'smtp', 'secure', 'vpn', 'api', 'dev', 'stage', 'test', 'ftp', 
        'admin', 'cloud', 'shop', 'store', 'app', 'mobile', 'beta',
        'portal', 'support', 'forum', 'web', 'media', 'img', 'images',
        'cdn', 'download', 'files', 'docs', 'help', 'video', 'tools'
    ]
    
    discovered_subdomains = []
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = []
        
        for subdomain in common_subdomains:
            full_subdomain = f"{subdomain}.{domain}"
            futures.append(
                executor.submit(resolve_subdomain, full_subdomain)
            )
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                discovered_subdomains.append(result)
    
    return discovered_subdomains

def passive_subdomain_scan(domain):
    """
    Realiza scan de subdomínios usando fontes passivas (APIs públicas).
    
    Args:
        domain (str): Domínio a ser escaneado
        
    Returns:
        list: Lista de subdomínios encontrados
    """
    logger.info(f"Realizando scan de subdomínios passivo em {domain}")
    
    discovered_subdomains = []
    
    # Lista de APIs públicas que podem ser usadas para descobrir subdomínios
    sources = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://api.hackertarget.com/hostsearch/?q={domain}"
    ]
    
    for source in sources:
        try:
            response = requests.get(source, timeout=10)
            
            if response.status_code == 200:
                if "crt.sh" in source:
                    # Parse do JSON da crt.sh
                    try:
                        data = response.json()
                        for entry in data:
                            name = entry.get('name_value')
                            if name and '*' not in name:
                                discovered_subdomains.append(name)
                    except:
                        pass
                
                elif "hackertarget" in source:
                    # Parse do texto da hackertarget
                    lines = response.text.splitlines()
                    for line in lines:
                        parts = line.split(',')
                        if len(parts) >= 1:
                            name = parts[0].strip()
                            if name and name != domain:
                                discovered_subdomains.append(name)
        except Exception as e:
            logger.error(f"Erro ao consultar fonte {source}: {str(e)}")
    
    # Remover duplicatas
    discovered_subdomains = list(set(discovered_subdomains))
    return discovered_subdomains

def resolve_subdomain(subdomain):
    """
    Tenta resolver um subdomínio para verificar sua existência.
    
    Args:
        subdomain (str): Subdomínio completo a ser resolvido
        
    Returns:
        str: Subdomínio se for resolvido, None caso contrário
    """
    try:
        dns.resolver.resolve(subdomain, 'A')
        return subdomain
    except:
        return None

def validate_subdomain(subdomain):
    """
    Valida um subdomínio verificando se ele está ativo e obtendo seu IP.
    
    Args:
        subdomain (str): Subdomínio a ser validado
        
    Returns:
        dict: Informações do subdomínio ou None se não for válido
    """
    try:
        # Obter IP do subdomínio
        ip = socket.gethostbyname(subdomain)
        
        # Tentar fazer uma requisição HTTP para verificar se está ativo
        status = None
        try:
            response = requests.head(f"http://{subdomain}", timeout=3)
            status = response.status_code
        except:
            try:
                response = requests.head(f"https://{subdomain}", timeout=3)
                status = response.status_code
            except:
                status = "timeout"
        
        return {
            'name': subdomain,
            'ip': ip,
            'status': status
        }
    except:
        return None
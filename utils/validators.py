#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import socket
from urllib.parse import urlparse

def validate_url(url, allow_ip=True):
    """
    Valida se uma string é uma URL válida.
    
    Args:
        url (str): URL a ser validada
        allow_ip (bool): Se True, aceita IPs como URLs válidas
    
    Returns:
        bool: True se a URL for válida, False caso contrário
    """
    # Verificar se a string está vazia
    if not url:
        return False
    
    # Adicionar esquema se não houver
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Analisar a URL
        parsed = urlparse(url)
        
        # Verificar se tem um esquema e um netloc (domínio)
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Verificar se o esquema é http ou https
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Se for um IP e allow_ip for False, retornar False
        if not allow_ip and validate_ip(parsed.netloc):
            return False
        
        # Verificar se o domínio tem pelo menos um ponto (a menos que seja localhost)
        if parsed.netloc != 'localhost' and '.' not in parsed.netloc:
            return False
        
        return True
    
    except Exception:
        return False

def validate_ip(ip):
    """
    Valida se uma string é um endereço IP válido.
    
    Args:
        ip (str): Endereço IP a ser validado
    
    Returns:
        bool: True se o IP for válido, False caso contrário
    """
    # Verificar se a string está vazia
    if not ip:
        return False
    
    # Remover a porta se estiver presente
    if ':' in ip:
        ip = ip.split(':')[0]
    
    # Usar a biblioteca socket para validar o IP
    try:
        socket.inet_aton(ip)
        
        # A função inet_aton não valida completamente IPv4
        # Verificar formato com expressão regular para IPv4
        if re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', ip):
            return True
        
        return False
    except:
        # Não é um IPv4 válido, pode ser um hostname
        return False

def validate_port_range(port_range):
    """
    Valida um range de portas.
    
    Args:
        port_range (str): Range de portas no formato "início-fim"
    
    Returns:
        bool: True se o range for válido, False caso contrário
    """
    if not port_range or '-' not in port_range:
        return False
    
    try:
        start, end = map(int, port_range.split('-'))
        
        # Verificar se as portas estão dentro do intervalo válido
        if start < 1 or start > 65535 or end < 1 or end > 65535:
            return False
        
        # Verificar se o início é menor que o fim
        if start > end:
            return False
        
        return True
    except ValueError:
        return False

def validate_domain(domain):
    """
    Valida se uma string é um nome de domínio válido.
    
    Args:
        domain (str): Nome de domínio a ser validado
    
    Returns:
        bool: True se o domínio for válido, False caso contrário
    """
    # Verificar se a string está vazia
    if not domain:
        return False
    
    # Remover protocolo se presente
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    # Remover a porta se estiver presente
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Validar com expressão regular
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
        return True
    
    return False

def validate_email(email):
    """
    Valida se uma string é um endereço de email válido.
    
    Args:
        email (str): Email a ser validado
    
    Returns:
        bool: True se o email for válido, False caso contrário
    """
    # Verificar se a string está vazia
    if not email:
        return False
    
    # Validar com expressão regular
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True
    
    return False

def sanitize_input(input_str, allow_html=False):
    """
    Sanitiza uma string de entrada para prevenir injeções.
    
    Args:
        input_str (str): String a ser sanitizada
        allow_html (bool): Se True, permite algumas tags HTML básicas
    
    Returns:
        str: String sanitizada
    """
    if not input_str:
        return ""
    
    # Converter para string caso não seja
    if not isinstance(input_str, str):
        input_str = str(input_str)
    
    if not allow_html:
        # Escapar caracteres HTML
        input_str = input_str.replace('&', '&amp;')
        input_str = input_str.replace('<', '&lt;')
        input_str = input_str.replace('>', '&gt;')
        input_str = input_str.replace('"', '&quot;')
        input_str = input_str.replace("'", '&#x27;')
        input_str = input_str.replace('/', '&#x2F;')
    else:
        # Permitir apenas algumas tags HTML seguras
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(input_str, 'html.parser')
        
        # Remover scripts e estilos
        for tag in soup(['script', 'style', 'iframe', 'object', 'embed', 'form']):
            tag.decompose()
        
        # Remover atributos perigosos
        for tag in soup.find_all(True):
            for attr in list(tag.attrs):
                if attr.startswith('on') or attr in ['href', 'src'] and tag.attrs[attr].startswith(('javascript:', 'data:')):
                    del tag.attrs[attr]
        
        input_str = str(soup)
    
    return input_str
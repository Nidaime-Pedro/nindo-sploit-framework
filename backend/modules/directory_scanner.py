#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

logger = logging.getLogger("nsf.directory_scanner")

# User-Agent para requisições
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Wordlists comuns
WORDLISTS = {
    'common': [
        'admin', 'wp-admin', 'administrator', 'login', 'wp-login.php', 'wp-login', 'wp-content',
        'backup', 'backups', 'database', 'db', 'bak', 'old', 'temp', 'tmp', 'test', 'testing',
        'dev', 'development', 'staging', 'prod', 'production', 'api', 'apis', 'v1', 'v2',
        'static', 'assets', 'uploads', 'images', 'img', 'css', 'js', 'fonts', 'media',
        'config', 'configuration', 'settings', 'setup', 'install', 'installer',
        'phpinfo.php', 'info.php', 'test.php', 'index.php', 'default.php', 'home.php',
        'about', 'contact', 'contactus', 'services', 'products', 'portfolio', 'blog',
        '.git', '.env', '.htaccess', '.svn', '.idea', '.vscode', '.DS_Store',
        'robots.txt', 'sitemap.xml', 'humans.txt', 'readme.md', 'README.md', 'CHANGELOG.md',
        'backup.zip', 'backup.tar.gz', 'backup.sql', 'dump.sql', 'database.sql'
    ],
    'big': 'wordlists/directories-big.txt',  # Arquivo com wordlist grande
    'small': 'wordlists/directories-small.txt'  # Arquivo com wordlist pequena
}

def scan_directories(target, wordlist='common', extensions=None):
    """
    Escaneia um site em busca de diretórios e arquivos ocultos.
    
    Args:
        target (str): URL alvo (ex: https://exemplo.com)
        wordlist (str): Tipo de wordlist a ser usada ('common', 'big', 'small')
        extensions (list): Lista de extensões de arquivo para verificar (ex: ['php', 'html'])
    
    Returns:
        dict: Resultado do scan com diretórios e arquivos encontrados
    """
    logger.info(f"Iniciando scan de diretórios em {target} (wordlist: {wordlist})")
    
    # Normalizar URL alvo
    if not target.endswith('/'):
        target += '/'
    
    # Certificar-se de que o esquema está presente (http:// ou https://)
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Obter a wordlist apropriada
    words = []
    if wordlist in WORDLISTS:
        if isinstance(WORDLISTS[wordlist], list):
            words = WORDLISTS[wordlist]
        else:
            # Carregar de arquivo
            try:
                wordlist_path = WORDLISTS[wordlist]
                if os.path.exists(wordlist_path):
                    with open(wordlist_path, 'r') as f:
                        words = [line.strip() for line in f if line.strip()]
                else:
                    logger.warning(f"Arquivo de wordlist não encontrado: {wordlist_path}. Usando wordlist comum.")
                    words = WORDLISTS['common']
            except Exception as e:
                logger.error(f"Erro ao carregar wordlist: {str(e)}")
                words = WORDLISTS['common']
    else:
        logger.warning(f"Wordlist '{wordlist}' não reconhecida. Usando wordlist comum.")
        words = WORDLISTS['common']
    
    # Verificar extensões
    if extensions is None:
        extensions = ['php', 'html', 'js', 'txt']
    elif isinstance(extensions, str):
        extensions = [ext.strip() for ext in extensions.split(',') if ext.strip()]
    
    # Expandir a wordlist com extensões
    expanded_words = []
    for word in words:
        expanded_words.append(word)  # Testar o próprio diretório/arquivo
        
        # Adicionar versões com extensões
        for ext in extensions:
            if not word.endswith('.' + ext):  # Evitar duplicatas
                expanded_words.append(f"{word}.{ext}")
    
    # Headers para requisições
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    
    # Função para verificar um único path
    def check_path(path):
        url = urljoin(target, path)
        try:
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
            status_code = response.status_code
            
            # Se for um redirect, obter o status code real do redirecionamento
            if status_code in (301, 302, 303, 307, 308):
                redirected_url = response.headers.get('Location', '')
                if redirected_url:
                    # Verificar se é um redirecionamento relativo ou absoluto
                    if not redirected_url.startswith(('http://', 'https://')):
                        redirected_url = urljoin(target, redirected_url)
                    
                    try:
                        # Fazer solicitação GET para o novo URL
                        redirect_response = requests.get(
                            redirected_url, 
                            headers=headers, 
                            timeout=5, 
                            allow_redirects=False
                        )
                        status_code = redirect_response.status_code
                    except:
                        # Se falhar, manter o código de status original
                        pass
            
            # Determinar se é interessante com base no código de status
            interesting = False
            if status_code < 400 or status_code in (401, 403):  # 2xx, 3xx, 401, 403
                interesting = True
            
            if interesting:
                # Obter o tamanho da resposta
                content_length = len(response.content)
                
                return {
                    'url': url,
                    'status': status_code,
                    'size': content_length,
                    'path': path
                }
            return None
        except requests.RequestException:
            return None
    
    # Realizar scan com múltiplas threads
    found_directories = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_path, path): path for path in expanded_words}
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_directories.append(result)
                logger.info(f"Encontrado: {result['url']} (Status: {result['status']}, Tamanho: {result['size']} bytes)")
    
    # Ordenar resultados por código de status e depois por URL
    found_directories.sort(key=lambda x: (x['status'], x['url']))
    
    return {
        'directories': found_directories,
        'total': len(found_directories),
        'target': target,
        'wordlist_used': wordlist,
        'extensions': extensions,
        'scanned_paths': len(expanded_words)
    }
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import base64
import binascii
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger("nsf.crypto_cracker")

# Algoritmos suportados para quebra
SUPPORTED_HASHES = ['md5', 'sha1', 'sha256', 'ntlm']
SUPPORTED_ENCODINGS = ['base64', 'hex', 'binary', 'caesar']

def crack_hash(hash_value: str, hash_type: str, wordlist: Union[str, List[str]], max_workers: int = 10) -> Dict:
    """
    Tenta quebrar um hash usando um ataque de dicionário.
    
    Args:
        hash_value (str): O valor de hash a ser quebrado
        hash_type (str): O tipo de hash (md5, sha1, etc.)
        wordlist (str ou list): Caminho para a wordlist ou lista de palavras
        max_workers (int): Número máximo de workers para processamento paralelo
    
    Returns:
        dict: Resultado da tentativa de quebra
    """
    logger.info(f"Iniciando quebra de hash {hash_type} usando wordlist")
    
    # Normalizar o hash
    hash_value = hash_value.lower().strip()
    
    # Verificar se o tipo de hash é suportado
    if hash_type.lower() not in SUPPORTED_HASHES:
        logger.error(f"Tipo de hash não suportado: {hash_type}")
        return {
            'success': False,
            'hash': hash_value,
            'hash_type': hash_type,
            'error': f"Tipo de hash não suportado: {hash_type}",
            'supported_hashes': SUPPORTED_HASHES
        }
    
    # Carregar wordlist
    words = []
    if isinstance(wordlist, str):
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                words = [line.strip() for line in f]
        except Exception as e:
            logger.error(f"Erro ao carregar wordlist: {str(e)}")
            return {
                'success': False,
                'hash': hash_value,
                'hash_type': hash_type,
                'error': f"Erro ao carregar wordlist: {str(e)}"
            }
    else:
        words = wordlist
    
    logger.info(f"Wordlist carregada com {len(words)} palavras")
    
    # Função para calcular hash de uma palavra
    def hash_word(word: str) -> Tuple[str, str]:
        if hash_type.lower() == 'md5':
            return word, hashlib.md5(word.encode()).hexdigest()
        elif hash_type.lower() == 'sha1':
            return word, hashlib.sha1(word.encode()).hexdigest()
        elif hash_type.lower() == 'sha256':
            return word, hashlib.sha256(word.encode()).hexdigest()
        elif hash_type.lower() == 'ntlm':
            # NTLM é usado pelo Windows
            try:
                import hashlib
                import binascii
                
                # Converter para Unicode LE e calcular o hash MD4
                word_utf16le = word.encode('utf-16le')
                md4_hash = hashlib.new('md4', word_utf16le).digest()
                ntlm_hash = binascii.hexlify(md4_hash).decode('utf-8')
                
                return word, ntlm_hash
            except Exception as e:
                logger.error(f"Erro ao calcular hash NTLM: {str(e)}")
                return word, ''
    
    # Quebrar o hash usando múltiplas threads
    result = None
    words_checked = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        
        for word in words:
            futures.append(executor.submit(hash_word, word))
        
        for future in as_completed(futures):
            words_checked += 1
            word, word_hash = future.result()
            
            if word_hash.lower() == hash_value.lower():
                result = word
                break
            
            # Log de progresso a cada 1000 palavras
            if words_checked % 1000 == 0:
                logger.info(f"Progresso: {words_checked}/{len(words)} palavras verificadas")
    
    # Preparar resultado
    if result:
        logger.info(f"Hash quebrado com sucesso: {result}")
        return {
            'success': True,
            'hash': hash_value,
            'hash_type': hash_type,
            'plaintext': result,
            'attempts': words_checked,
            'total_words': len(words)
        }
    else:
        logger.info(f"Não foi possível quebrar o hash após {words_checked} tentativas")
        return {
            'success': False,
            'hash': hash_value,
            'hash_type': hash_type,
            'attempts': words_checked,
            'total_words': len(words),
            'message': "Não foi possível encontrar correspondência na wordlist fornecida"
        }

def decode_string(encoded_string: str, encoding_type: str, shift: int = None) -> Dict:
    """
    Decodifica uma string codificada.
    
    Args:
        encoded_string (str): A string codificada
        encoding_type (str): O tipo de codificação (base64, hex, etc.)
        shift (int): Deslocamento para cifra de César (opcional)
    
    Returns:
        dict: Resultado da decodificação
    """
    logger.info(f"Tentando decodificar string usando {encoding_type}")
    
    # Verificar se o tipo de codificação é suportado
    if encoding_type.lower() not in SUPPORTED_ENCODINGS:
        logger.error(f"Tipo de codificação não suportado: {encoding_type}")
        return {
            'success': False,
            'encoded': encoded_string,
            'encoding_type': encoding_type,
            'error': f"Tipo de codificação não suportado: {encoding_type}",
            'supported_encodings': SUPPORTED_ENCODINGS
        }
    
    try:
        # Decodificar com base no tipo
        if encoding_type.lower() == 'base64':
            # Base64
            decoded = base64.b64decode(encoded_string).decode('utf-8')
            return {
                'success': True,
                'encoded': encoded_string,
                'encoding_type': encoding_type,
                'decoded': decoded
            }
        
        elif encoding_type.lower() == 'hex':
            # Hexadecimal
            decoded = binascii.unhexlify(encoded_string).decode('utf-8')
            return {
                'success': True,
                'encoded': encoded_string,
                'encoding_type': encoding_type,
                'decoded': decoded
            }
        
        elif encoding_type.lower() == 'binary':
            # Binário para texto
            try:
                # Remover espaços e verificar se é binário válido
                binary = encoded_string.replace(' ', '')
                if not all(bit in '01' for bit in binary):
                    raise ValueError("Entrada não é um binário válido")
                
                # Verificar se o comprimento é múltiplo de 8
                if len(binary) % 8 != 0:
                    binary = binary.zfill((len(binary) // 8 + 1) * 8)
                
                # Converter para texto
                decoded = ''.join([chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)])
                
                return {
                    'success': True,
                    'encoded': encoded_string,
                    'encoding_type': encoding_type,
                    'decoded': decoded
                }
            except Exception as e:
                return {
                    'success': False,
                    'encoded': encoded_string,
                    'encoding_type': encoding_type,
                    'error': f"Erro ao decodificar binário: {str(e)}"
                }
        
        elif encoding_type.lower() == 'caesar':
            # Cifra de César
            if shift is None:
                # Se não fornecido, tentar todos os deslocamentos
                decoded_options = []
                
                for s in range(1, 26):
                    decoded = caesar_cipher(encoded_string, s, decode=True)
                    decoded_options.append({
                        'shift': s,
                        'text': decoded
                    })
                
                return {
                    'success': True,
                    'encoded': encoded_string,
                    'encoding_type': encoding_type,
                    'results': decoded_options
                }
            else:
                # Decodificar com o deslocamento fornecido
                decoded = caesar_cipher(encoded_string, shift, decode=True)
                return {
                    'success': True,
                    'encoded': encoded_string,
                    'encoding_type': encoding_type,
                    'shift': shift,
                    'decoded': decoded
                }
    
    except Exception as e:
        logger.error(f"Erro ao decodificar {encoding_type}: {str(e)}")
        return {
            'success': False,
            'encoded': encoded_string,
            'encoding_type': encoding_type,
            'error': f"Erro ao decodificar: {str(e)}"
        }

def caesar_cipher(text: str, shift: int, decode: bool = False) -> str:
    """
    Implementa a cifra de César para codificar/decodificar texto.
    
    Args:
        text (str): Texto a ser codificado/decodificado
        shift (int): Valor do deslocamento
        decode (bool): True para decodificar, False para codificar
    
    Returns:
        str: Texto codificado/decodificado
    """
    # Ajustar deslocamento para decodificação
    if decode:
        shift = 26 - (shift % 26)
    else:
        shift = shift % 26
    
    result = ""
    
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            # Deslocar o caractere e aplicar módulo 26
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            # Manter caracteres não alfabéticos
            result += char
    
    return result

def estimate_crack_time(hash_type: str, wordlist_size: int) -> Dict:
    """
    Estima o tempo necessário para quebrar um hash.
    
    Args:
        hash_type (str): O tipo de hash
        wordlist_size (int): Tamanho da wordlist
    
    Returns:
        dict: Estimativa de tempo
    """
    # Valores aproximados de hashes por segundo em hardware comum
    hash_speeds = {
        'md5': 1000000000,  # 1 bilhão/s
        'sha1': 500000000,  # 500 milhões/s
        'sha256': 100000000,  # 100 milhões/s
        'sha512': 50000000,  # 50 milhões/s
        'bcrypt': 10000,    # 10 mil/s
        'ntlm': 1000000000  # 1 bilhão/s
    }
    
    if hash_type.lower() not in hash_speeds:
        return {
            'hash_type': hash_type,
            'wordlist_size': wordlist_size,
            'error': f"Tipo de hash não suportado para estimativa: {hash_type}"
        }
    
    # Calcular tempo estimado
    seconds = wordlist_size / hash_speeds[hash_type.lower()]
    
    # Converter para unidades mais legíveis
    if seconds < 60:
        time_unit = 'segundos'
        time_value = seconds
    elif seconds < 3600:
        time_unit = 'minutos'
        time_value = seconds / 60
    elif seconds < 86400:
        time_unit = 'horas'
        time_value = seconds / 3600
    else:
        time_unit = 'dias'
        time_value = seconds / 86400
    
    return {
        'hash_type': hash_type,
        'wordlist_size': wordlist_size,
        'estimated_time_seconds': seconds,
        'estimated_time': f"{time_value:.2f} {time_unit}",
        'hash_speed': hash_speeds[hash_type.lower()]
    }
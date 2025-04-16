#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import hashlib
import logging
import base64
from typing import Dict, List, Tuple

logger = logging.getLogger("nsf.hash_analyzer")

# Configurações
HASH_PATTERNS = {
    'md5': (r'^[a-f0-9]{32}$', 'MD5'),
    'sha1': (r'^[a-f0-9]{40}$', 'SHA-1'),
    'sha256': (r'^[a-f0-9]{64}$', 'SHA-256'),
    'sha512': (r'^[a-f0-9]{128}$', 'SHA-512'),
    'ntlm': (r'^[a-f0-9]{32}$', 'NTLM'),
    'bcrypt': (r'^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$', 'bcrypt'),
    'mysql': (r'^[a-f0-9]{16}$', 'MySQL3.x'),
    'mysql4': (r'^[a-f0-9]{41}$', 'MySQL4.x'),
    'wordpress': (r'^\$P\$[a-zA-Z0-9./]{31}$', 'WordPress'),
    'sha3_224': (r'^[a-f0-9]{56}$', 'SHA3-224'),
    'sha3_256': (r'^[a-f0-9]{64}$', 'SHA3-256'),
    'sha3_384': (r'^[a-f0-9]{96}$', 'SHA3-384'),
    'sha3_512': (r'^[a-f0-9]{128}$', 'SHA3-512'),
    'md4': (r'^[a-f0-9]{32}$', 'MD4'),
    'ripemd160': (r'^[a-f0-9]{40}$', 'RIPEMD-160'),
    'whirlpool': (r'^[a-f0-9]{128}$', 'Whirlpool'),
    'base64': (r'^[A-Za-z0-9+/]+={0,2}$', 'Base64')
}

# Hashes mais comuns
COMMON_HASHES = {
    'md5': {
        'length': 32,
        'complexity': 'Medium',
        'crackability': 'High',
        'description': '128-bit hash, commonly used but insecure for passwords'
    },
    'sha1': {
        'length': 40,
        'complexity': 'Medium',
        'crackability': 'Medium-High',
        'description': '160-bit hash, widely used but vulnerable to collision attacks'
    },
    'sha256': {
        'length': 64,
        'complexity': 'High',
        'crackability': 'Medium',
        'description': '256-bit hash, part of SHA-2 family, more secure than SHA-1'
    },
    'sha512': {
        'length': 128,
        'complexity': 'Very High',
        'crackability': 'Low-Medium',
        'description': '512-bit hash, part of SHA-2 family, more secure than SHA-256'
    },
    'bcrypt': {
        'length': 60,
        'complexity': 'Very High',
        'crackability': 'Low',
        'description': 'Slow hash function with salt, designed for password storage'
    },
    'ntlm': {
        'length': 32,
        'complexity': 'Medium',
        'crackability': 'High',
        'description': 'Used by Windows for password storage, relatively weak'
    }
}

def analyze_hash(hash_value: str) -> Dict:
    """
    Analisa um valor de hash para identificar seu tipo, características e gera informações adicionais.
    
    Args:
        hash_value (str): O valor de hash a ser analisado
    
    Returns:
        dict: Informações sobre o hash analisado
    """
    logger.info(f"Analisando hash: {hash_value}")
    
    # Limpar e normalizar o hash
    hash_value = hash_value.strip()
    
    # Tentar identificar o tipo de hash
    identified_types = []
    for hash_type, (pattern, name) in HASH_PATTERNS.items():
        if re.match(pattern, hash_value):
            identified_types.append({
                'type': hash_type,
                'name': name
            })
    
    # Se não for identificado nenhum tipo de hash
    if not identified_types:
        logger.warning(f"Não foi possível identificar o tipo do hash: {hash_value}")
        return {
            'hash': hash_value,
            'identified_types': [],
            'possible_types': [],
            'length': len(hash_value),
            'entropy': calculate_entropy(hash_value),
            'character_distribution': analyze_characters(hash_value),
            'is_base64': is_base64(hash_value),
            'recommendation': 'O valor fornecido não parece ser um hash conhecido.'
        }
    
    # Obter tipos mais prováveis com base no comprimento e padrão
    primary_matches = []
    secondary_matches = []
    
    for hash_info in identified_types:
        hash_type = hash_info['type']
        if hash_type in COMMON_HASHES:
            info = COMMON_HASHES[hash_type].copy()
            info['type'] = hash_type
            info['name'] = hash_info['name']
            primary_matches.append(info)
        else:
            secondary_matches.append(hash_info)
    
    # Verificar se pode ser Base64
    is_base64_encoded = is_base64(hash_value)
    
    # Tentar decodificar se for Base64
    base64_decoded = None
    if is_base64_encoded:
        try:
            base64_decoded = base64.b64decode(hash_value).decode('utf-8')
        except:
            base64_decoded = None
    
    # Calcular entropia
    entropy = calculate_entropy(hash_value)
    
    # Gerar recomendações com base no tipo de hash
    recommendations = generate_recommendations(identified_types)
    
    # Preparar resultado da análise
    result = {
        'hash': hash_value,
        'identified_types': identified_types,
        'most_likely_types': primary_matches,
        'other_possible_types': secondary_matches,
        'length': len(hash_value),
        'entropy': entropy,
        'character_distribution': analyze_characters(hash_value),
        'is_base64': is_base64_encoded,
        'base64_decoded': base64_decoded,
        'recommendations': recommendations
    }
    
    logger.info(f"Análise de hash concluída: {len(identified_types)} tipos identificados")
    return result

def calculate_entropy(data: str) -> float:
    """
    Calcula a entropia de Shannon de uma string.
    
    Args:
        data (str): A string para calcular a entropia
    
    Returns:
        float: Valor da entropia
    """
    import math
    
    # Contar ocorrências de cada caractere
    char_count = {}
    for char in data:
        char_count[char] = char_count.get(char, 0) + 1
    
    # Calcular entropia
    entropy = 0
    for count in char_count.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_characters(data: str) -> Dict:
    """
    Analisa a distribuição de caracteres em uma string.
    
    Args:
        data (str): A string para analisar
    
    Returns:
        dict: Estatísticas de distribuição de caracteres
    """
    # Categorias de caracteres
    categories = {
        'lowercase': 0,
        'uppercase': 0,
        'digits': 0,
        'special': 0
    }
    
    # Contar cada tipo de caractere
    for char in data:
        if char.islower():
            categories['lowercase'] += 1
        elif char.isupper():
            categories['uppercase'] += 1
        elif char.isdigit():
            categories['digits'] += 1
        else:
            categories['special'] += 1
    
    # Calcular percentagens
    total = len(data)
    for category in categories:
        categories[category] = {
            'count': categories[category],
            'percentage': round((categories[category] / total) * 100, 2)
        }
    
    return categories

def is_base64(data: str) -> bool:
    """
    Verifica se uma string pode ser Base64.
    
    Args:
        data (str): A string para verificar
    
    Returns:
        bool: True se puder ser Base64, False caso contrário
    """
    # Padrão regex para Base64
    if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
        return False
    
    # Verificar comprimento (múltiplo de 4)
    if len(data) % 4 != 0:
        return False
    
    # Tentar decodificar
    try:
        decoded = base64.b64decode(data)
        return True
    except:
        return False

def generate_recommendations(identified_types: List[Dict]) -> List[str]:
    """
    Gera recomendações com base nos tipos de hash identificados.
    
    Args:
        identified_types (list): Lista de tipos de hash identificados
    
    Returns:
        list: Lista de recomendações
    """
    recommendations = []
    
    # Verificar se tem algum tipo identificado
    if not identified_types:
        recommendations.append("O valor fornecido não parece ser um hash conhecido.")
        recommendations.append("Verifique se o valor foi inserido corretamente.")
        return recommendations
    
    # Recomendações gerais
    recommendations.append("Para quebrar hashes, considere usar rainbow tables, dicionários ou força bruta.")
    
    # Recomendações específicas por tipo
    hash_types = [h['type'] for h in identified_types]
    
    if 'md5' in hash_types or 'sha1' in hash_types:
        recommendations.append("Os hashes MD5 e SHA-1 são considerados obsoletos para armazenamento de senhas devido à sua vulnerabilidade a ataques de força bruta.")
        recommendations.append("Recomenda-se usar hashcat ou John the Ripper para tentar quebrar esses hashes.")
    
    if 'sha256' in hash_types or 'sha512' in hash_types:
        recommendations.append("Os hashes SHA-256 e SHA-512 são mais seguros, mas podem ser vulneráveis a ataques de força bruta ou dicionário se a senha original for fraca.")
    
    if 'bcrypt' in hash_types:
        recommendations.append("bcrypt é um algoritmo projetado para ser resistente a ataques de força bruta devido ao seu fator de custo ajustável.")
        recommendations.append("Quebrar bcrypt normalmente exige muito mais recursos computacionais.")
    
    if 'ntlm' in hash_types:
        recommendations.append("Hashes NTLM são frequentemente alvo de ataques pass-the-hash. Considere usar ferramentas especializadas como Mimikatz para explorar essa vulnerabilidade.")
    
    return recommendations

def hash_string(input_string: str, algorithms: List[str]) -> Dict:
    """
    Calcula o hash de uma string usando vários algoritmos.
    
    Args:
        input_string (str): A string para calcular o hash
        algorithms (list): Lista de algoritmos a serem usados
    
    Returns:
        dict: Hashes gerados por cada algoritmo
    """
    logger.info(f"Calculando hash para string usando {len(algorithms)} algoritmos")
    
    results = {}
    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha3_224': hashlib.sha3_224,
        'sha3_256': hashlib.sha3_256,
        'sha3_384': hashlib.sha3_384,
        'sha3_512': hashlib.sha3_512
    }
    
    for algorithm in algorithms:
        if algorithm.lower() in hash_functions:
            hash_function = hash_functions[algorithm.lower()]
            hash_value = hash_function(input_string.encode()).hexdigest()
            results[algorithm] = hash_value
    
    return {
        'input': input_string,
        'hashes': results
    }
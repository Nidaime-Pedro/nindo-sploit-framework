import nmap
import socket
import threading
import concurrent.futures
import logging

logger = logging.getLogger("nsf.port_scanner")

def scan_port(ip, port):
    """Escaneia uma única porta em um host."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    if result == 0:
        return port
    return None

def scan_ports(target, port_range='1-1000'):
    """
    Escaneia portas em um alvo usando thread pool para melhor performance.
    
    Args:
        target (str): IP ou hostname para escanear
        port_range (str): Range de portas no formato "início-fim"
    
    Returns:
        dict: Resultado do scan com portas abertas e detalhes
    """
    logger.info(f"Iniciando scanner de portas em {target} (range: {port_range})")
    
    try:
        # Se for um hostname, resolver para IP
        if not target.replace('.', '').isdigit():
            target_ip = socket.gethostbyname(target)
        else:
            target_ip = target
        
        # Parsear range de portas
        start_port, end_port = map(int, port_range.split('-'))
        
        open_ports = []
        
        # Scanner rápido usando threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            port_futures = {
                executor.submit(scan_port, target_ip, port): port
                for port in range(start_port, end_port + 1)
            }
            
            for future in concurrent.futures.as_completed(port_futures):
                port = future.result()
                if port:
                    open_ports.append(port)
        
        # Para portas abertas, usar nmap para obter mais detalhes
        port_details = {}
        
        if open_ports:
            logger.info(f"Encontradas {len(open_ports)} portas abertas. Obtendo detalhes...")
            
            nm = nmap.PortScanner()
            
            for port in open_ports:
                try:
                    # Escanear com nmap para obter detalhes da porta
                    nm.scan(target_ip, str(port), arguments='-sV')
                    
                    if target_ip in nm.all_hosts() and 'tcp' in nm[target_ip] and port in nm[target_ip]['tcp']:
                        port_info = nm[target_ip]['tcp'][port]
                        port_details[port] = {
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'state': port_info.get('state', '')
                        }
                    else:
                        port_details[port] = {
                            'service': 'unknown',
                            'product': '',
                            'version': '',
                            'state': 'open'
                        }
                except Exception as e:
                    logger.error(f"Erro ao obter detalhes da porta {port}: {str(e)}")
                    port_details[port] = {
                        'service': 'unknown',
                        'product': '',
                        'version': '',
                        'error': str(e),
                        'state': 'open'
                    }
        
        # Preparar resultado
        result = {
            'open_ports': sorted(open_ports),
            'port_details': port_details,
            'total_open': len(open_ports),
            'scanned_range': port_range,
            'host': target
        }
        
        return result
    
    except Exception as e:
        logger.error(f"Erro ao escanear portas: {str(e)}")
        raise
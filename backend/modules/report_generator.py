import os
import json
import markdown
from datetime import datetime
from fpdf import FPDF
import logging

logger = logging.getLogger("nsf.report_generator")

def generate_report_markdown(scan_results, title="NSF Security Report", company_name="", author=""):
    """
    Gera um relatório em formato Markdown a partir dos resultados de scans.
    
    Args:
        scan_results (list): Lista de resultados de scans
        title (str): Título do relatório
        company_name (str): Nome da empresa (opcional)
        author (str): Nome do autor (opcional)
    
    Returns:
        str: Conteúdo do relatório em formato Markdown
    """
    logger.info("Gerando relatório em formato Markdown")
    
    # Cabeçalho do relatório
    report = f"# {title}\n\n"
    
    if company_name:
        report += f"**Empresa:** {company_name}\n\n"
    
    if author:
        report += f"**Autor:** {author}\n\n"
    
    # Data e hora da geração
    now = datetime.now()
    report += f"**Data:** {now.strftime('%d/%m/%Y %H:%M:%S')}\n\n"
    
    # Resumo
    report += "## Resumo\n\n"
    
    scan_types = {}
    targets = set()
    vulnerabilities = 0
    
    for result in scan_results:
        scan_type = result.get('scan_type', 'unknown')
        scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        targets.add(result.get('target', ''))
        
        # Contar vulnerabilidades
        if scan_type in ['sqli_scan', 'xss_scan', 'redirect_scan']:
            vulnerabilities += len([v for v in result.get('vulnerabilities', []) if v.get('vulnerable')])
        elif scan_type == 'bruteforce':
            vulnerabilities += len(result.get('successful_attempts', []))
        elif scan_type == 'bypass_403':
            vulnerabilities += len(result.get('successful_techniques', []))
    
    report += f"- **Total de Scans:** {len(scan_results)}\n"
    report += f"- **Alvos Escaneados:** {len(targets)}\n"
    report += f"- **Vulnerabilidades Encontradas:** {vulnerabilities}\n\n"
    
    report += "### Tipos de Scans Realizados\n\n"
    for scan_type, count in scan_types.items():
        # Formatar o tipo de scan para exibição
        scan_type_display = scan_type.replace('_', ' ').title()
        report += f"- **{scan_type_display}:** {count}\n"
    
    report += "\n## Resultados Detalhados\n\n"
    
    # Ordenar resultados por tipo de scan
    scan_results_sorted = sorted(scan_results, key=lambda x: x.get('scan_type', ''))
    
    # Detalhes de cada scan
    for result in scan_results_sorted:
        scan_type = result.get('scan_type', 'unknown')
        target = result.get('target', 'N/A')
        timestamp = result.get('timestamp', '')
        scan_time = result.get('scan_time', 0)
        
        # Formatar o timestamp
        try:
            timestamp_formatted = datetime.fromisoformat(timestamp).strftime('%d/%m/%Y %H:%M:%S')
        except:
            timestamp_formatted = timestamp
        
        # Título do scan
        scan_type_display = scan_type.replace('_', ' ').title()
        report += f"### {scan_type_display} - {target}\n\n"
        
        # Metadados
        report += f"- **Alvo:** {target}\n"
        report += f"- **Data e Hora:** {timestamp_formatted}\n"
        report += f"- **Tempo de Execução:** {scan_time} segundos\n\n"
        
        # Detalhes específicos para cada tipo de scan
        if scan_type == 'port_scan':
            report += _format_port_scan_results(result)
        elif scan_type == 'directory_scan':
            report += _format_directory_scan_results(result)
        elif scan_type == 'subdomain_scan':
            report += _format_subdomain_scan_results(result)
        elif scan_type == 'technology_scan':
            report += _format_technology_scan_results(result)
        elif scan_type == 'plugin_scan':
            report += _format_plugin_scan_results(result)
        elif scan_type == 'sqli_scan':
            report += _format_vulnerability_scan_results(result, 'SQL Injection')
        elif scan_type == 'xss_scan':
            report += _format_vulnerability_scan_results(result, 'Cross-Site Scripting (XSS)')
        elif scan_type == 'redirect_scan':
            report += _format_vulnerability_scan_results(result, 'Open Redirect')
        elif scan_type == 'bruteforce':
            report += _format_bruteforce_results(result)
        elif scan_type == 'bypass_403':
            report += _format_bypass_403_results(result)
        
        report += "\n\n"
    
    # Recomendações
    report += "## Recomendações\n\n"
    
    if vulnerabilities > 0:
        report += "Com base nos resultados encontrados, recomendamos as seguintes ações:\n\n"
        
        # Adicionar recomendações específicas baseadas nas vulnerabilidades encontradas
        recommendations = set()
        
        for result in scan_results:
            scan_type = result.get('scan_type', '')
            
            if scan_type == 'port_scan':
                if result.get('total_open', 0) > 0:
                    recommendations.add("- Fechar portas desnecessárias e aplicar firewall para restringir o acesso.")
            
            elif scan_type == 'sqli_scan':
                if any(v.get('vulnerable') for v in result.get('vulnerabilities', [])):
                    recommendations.add("- Implementar parametrização de consultas SQL e validação de entrada para prevenir SQL Injection.")
            
            elif scan_type == 'xss_scan':
                if any(v.get('vulnerable') for v in result.get('vulnerabilities', [])):
                    recommendations.add("- Implementar sanitização de entrada e saída para prevenir ataques XSS.")
                    recommendations.add("- Configurar cabeçalhos de segurança como Content-Security-Policy.")
            
            elif scan_type == 'redirect_scan':
                if any(v.get('vulnerable') for v in result.get('vulnerabilities', [])):
                    recommendations.add("- Validar e sanitizar parâmetros de redirecionamento para prevenir Open Redirect.")
            
            elif scan_type == 'bruteforce' and result.get('successful_attempts', []):
                recommendations.add("- Implementar proteção contra força bruta como CAPTCHA e bloqueio temporário após múltiplas tentativas falhas.")
                recommendations.add("- Utilizar políticas de senha forte e autenticação de dois fatores.")
        
        # Adicionar recomendações gerais se não houver específicas
        if not recommendations:
            recommendations.add("- Realizar revisões de código e testes de segurança regularmente.")
            recommendations.add("- Manter sistemas e bibliotecas atualizados.")
            recommendations.add("- Implementar um programa de gestão de vulnerabilidades.")
        
        for recommendation in sorted(recommendations):
            report += f"{recommendation}\n"
    else:
        report += "Nenhuma vulnerabilidade significativa foi encontrada durante os testes. Recomendamos manter as boas práticas de segurança:\n\n"
        report += "- Continuidade dos testes de segurança periodicamente\n"
        report += "- Manter sistemas e bibliotecas atualizados\n"
        report += "- Implementar um programa de resposta a incidentes\n"
    
    # Rodapé
    report += "\n\n---\n\n"
    report += "_Relatório gerado automaticamente pela plataforma NSF (Nindo Sploit Framework)._\n"
    
    return report

def _format_port_scan_results(result):
    """Formatar resultados do scan de portas para o relatório."""
    output = ""
    open_ports = result.get('open_ports', [])
    port_details = result.get('port_details', {})
    
    output += f"**Portas Abertas:** {len(open_ports)}\n\n"
    
    if open_ports:
        output += "| Porta | Serviço | Produto | Versão |\n"
        output += "|-------|---------|---------|--------|\n"
        
        for port in open_ports:
            details = port_details.get(str(port), {})
            service = details.get('service', 'unknown')
            product = details.get('product', '')
            version = details.get('version', '')
            
            output += f"| {port} | {service} | {product} | {version} |\n"
    else:
        output += "Nenhuma porta aberta encontrada.\n"
    
    return output

def _format_directory_scan_results(result):
    """Formatar resultados do scan de diretórios para o relatório."""
    output = ""
    directories = result.get('directories', [])
    
    output += f"**Diretórios/Arquivos Encontrados:** {len(directories)}\n\n"
    
    if directories:
        output += "| URL | Código de Status | Tamanho (bytes) |\n"
        output += "|-----|-----------------|----------------|\n"
        
        for directory in directories:
            url = directory.get('url', 'N/A')
            status = directory.get('status', 'N/A')
            size = directory.get('size', 'N/A')
            
            output += f"| {url} | {status} | {size} |\n"
    else:
        output += "Nenhum diretório ou arquivo relevante encontrado.\n"
    
    return output

def _format_subdomain_scan_results(result):
    """Formatar resultados do scan de subdomains para o relatório."""
    output = ""
    subdomains = result.get('subdomains', [])
    
    output += f"**Subdomínios Encontrados:** {len(subdomains)}\n\n"
    
    if subdomains:
        output += "| Subdomínio | IP | Status |\n"
        output += "|------------|----|---------|\n"
        
        for subdomain in subdomains:
            name = subdomain.get('name', 'N/A')
            ip = subdomain.get('ip', 'N/A')
            status = subdomain.get('status', 'N/A')
            
            output += f"| {name} | {ip} | {status} |\n"
    else:
        output += "Nenhum subdomínio encontrado.\n"
    
    return output

def _format_technology_scan_results(result):
    """Formatar resultados do scan de tecnologias para o relatório."""
    output = ""
    technologies = result.get('technologies', [])
    
    output += f"**Tecnologias Detectadas:** {len(technologies)}\n\n"
    
    if technologies:
        output += "| Tecnologia | Categoria | Versão |\n"
        output += "|------------|-----------|--------|\n"
        
        for tech in technologies:
            name = tech.get('name', 'N/A')
            category = tech.get('category', 'N/A')
            version = tech.get('version', 'N/A')
            
            output += f"| {name} | {category} | {version} |\n"
    else:
        output += "Nenhuma tecnologia detectada.\n"
    
    return output

def _format_plugin_scan_results(result):
    """Formatar resultados do scan de plugins para o relatório."""
    output = ""
    plugins = result.get('plugins', [])
    cms = result.get('cms', 'unknown')
    
    output += f"**CMS Detectado:** {cms}\n"
    output += f"**Plugins Encontrados:** {len(plugins)}\n\n"
    
    if plugins:
        output += "| Plugin | Versão | Status | Vulnerabilidades Conhecidas |\n"
        output += "|--------|--------|--------|-----------------------------|\n"
        
        for plugin in plugins:
            name = plugin.get('name', 'N/A')
            version = plugin.get('version', 'N/A')
            status = plugin.get('status', 'ativo')
            vulns = plugin.get('vulnerabilities', 0)
            
            output += f"| {name} | {version} | {status} | {vulns} |\n"
    else:
        output += "Nenhum plugin detectado.\n"
    
    return output

def _format_vulnerability_scan_results(result, vuln_type):
    """Formatar resultados do scan de vulnerabilidades para o relatório."""
    output = ""
    vulnerabilities = result.get('vulnerabilities', [])
    
    # Filtrar apenas vulnerabilidades confirmadas
    confirmed_vulns = [v for v in vulnerabilities if v.get('vulnerable')]
    
    output += f"**Vulnerabilidades {vuln_type} Encontradas:** {len(confirmed_vulns)}\n\n"
    
    if confirmed_vulns:
        output += "| URL/Parâmetro | Payload | Detalhes |\n"
        output += "|---------------|---------|----------|\n"
        
        for vuln in confirmed_vulns:
            url = vuln.get('url', 'N/A')
            payload = vuln.get('payload', 'N/A')
            details = vuln.get('details', 'N/A')
            
            output += f"| {url} | {payload} | {details} |\n"
    else:
        output += f"Nenhuma vulnerabilidade {vuln_type} encontrada.\n"
    
    return output

def _format_bruteforce_results(result):
    """Formatar resultados do brute force para o relatório."""
    output = ""
    successful_attempts = result.get('successful_attempts', [])
    mode = result.get('mode', 'login')
    
    output += f"**Modo de Brute Force:** {mode}\n"
    output += f"**Credenciais Válidas Encontradas:** {len(successful_attempts)}\n\n"
    
    if successful_attempts:
        output += "| Usuário | Senha |\n"
        output += "|---------|-------|\n"
        
        for attempt in successful_attempts:
            username = attempt.get('username', 'N/A')
            password = attempt.get('password', 'N/A')
            
            output += f"| {username} | {password} |\n"
    else:
        output += "Nenhuma credencial válida encontrada.\n"
    
    return output

def _format_bypass_403_results(result):
    """Formatar resultados do bypass 403 para o relatório."""
    output = ""
    successful_techniques = result.get('successful_techniques', [])
    
    output += f"**Técnicas de Bypass 403 Bem-sucedidas:** {len(successful_techniques)}\n\n"
    
    if successful_techniques:
        output += "| Técnica | Método | URL | Código de Status |\n"
        output += "|---------|--------|-----|------------------|\n"
        
        for technique in successful_techniques:
            name = technique.get('name', 'N/A')
            method = technique.get('method', 'GET')
            url = technique.get('url', 'N/A')
            status = technique.get('status', 'N/A')
            
            output += f"| {name} | {method} | {url} | {status} |\n"
    else:
        output += "Nenhuma técnica de bypass 403 bem-sucedida encontrada.\n"
    
    return output

def generate_report_pdf(scan_results, title="NSF Security Report", company_name="", author=""):
    """
    Gera um relatório em formato PDF a partir dos resultados de scans.
    
    Args:
        scan_results (list): Lista de resultados de scans
        title (str): Título do relatório
        company_name (str): Nome da empresa (opcional)
        author (str): Nome do autor (opcional)
    
    Returns:
        str: Caminho para o arquivo PDF gerado
    """
    logger.info("Gerando relatório em formato PDF")
    
    # Primeiro, gerar o markdown
    markdown_content = generate_report_markdown(scan_results, title, company_name, author)
    
    # Criar um nome de arquivo baseado no timestamp
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    report_filename = f"nsf_report_{timestamp}.pdf"
    report_path = os.path.join(os.getcwd(), "reports", report_filename)
    
    # Garantir que o diretório de relatórios existe
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    # Converter markdown para HTML
    html_content = markdown.markdown(markdown_content, extensions=['tables'])
    
    # Criar PDF usando FPDF
    pdf = FPDF()
    pdf.add_page()
    
    # Configurar fontes
    pdf.set_font("Arial", "B", 16)
    
    # Título
    pdf.cell(0, 10, title, ln=True, align="C")
    pdf.ln(5)
    
    # Metadados
    pdf.set_font("Arial", "", 12)
    
    if company_name:
        pdf.cell(0, 10, f"Empresa: {company_name}", ln=True)
    
    if author:
        pdf.cell(0, 10, f"Autor: {author}", ln=True)
    
    now = datetime.now()
    pdf.cell(0, 10, f"Data: {now.strftime('%d/%m/%Y %H:%M:%S')}", ln=True)
    pdf.ln(5)
    
    # Como a conversão de HTML para PDF não é trivial com FPDF,
    # vamos fazer uma versão simplificada do relatório
    
    # Resumo
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Resumo", ln=True)
    pdf.ln(2)
    
    pdf.set_font("Arial", "", 12)
    
    scan_types = {}
    targets = set()
    vulnerabilities = 0
    
    for result in scan_results:
        scan_type = result.get('scan_type', 'unknown')
        scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        targets.add(result.get('target', ''))
        
        # Contar vulnerabilidades
        if scan_type in ['sqli_scan', 'xss_scan', 'redirect_scan']:
            vulnerabilities += len([v for v in result.get('vulnerabilities', []) if v.get('vulnerable')])
        elif scan_type == 'bruteforce':
            vulnerabilities += len(result.get('successful_attempts', []))
        elif scan_type == 'bypass_403':
            vulnerabilities += len(result.get('successful_techniques', []))
    
    pdf.cell(0, 10, f"Total de Scans: {len(scan_results)}", ln=True)
    pdf.cell(0, 10, f"Alvos Escaneados: {len(targets)}", ln=True)
    pdf.cell(0, 10, f"Vulnerabilidades Encontradas: {vulnerabilities}", ln=True)
    pdf.ln(5)
    
    # Tipos de scans
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Tipos de Scans Realizados", ln=True)
    pdf.set_font("Arial", "", 12)
    
    for scan_type, count in scan_types.items():
        scan_type_display = scan_type.replace('_', ' ').title()
        pdf.cell(0, 10, f"- {scan_type_display}: {count}", ln=True)
    
    # Para cada tipo de resultado, adicionar detalhes relevantes
    # Aqui incluiríamos código para formatar cada tipo de scan
    
    # Salvar PDF
    pdf.output(report_path)
    
    logger.info(f"Relatório PDF gerado em: {report_path}")
    return report_path
<?php
// Verificar se o parâmetro do arquivo foi fornecido
if (!isset($_GET['file']) || empty($_GET['file'])) {
    http_response_code(400);
    echo "Erro: Parâmetro 'file' não fornecido.";
    exit;
}

// Obter o caminho do arquivo
$file_path = $_GET['file'];

// Verificar se o caminho está dentro do diretório de relatórios (segurança)
$reports_dir = realpath(__DIR__ . '/../../backend/reports');
$requested_file = realpath($file_path);

if ($requested_file === false || strpos($requested_file, $reports_dir) !== 0) {
    http_response_code(403);
    echo "Erro: Acesso não autorizado ao arquivo solicitado.";
    exit;
}

// Verificar se o arquivo existe
if (!file_exists($requested_file)) {
    http_response_code(404);
    echo "Erro: Arquivo não encontrado.";
    exit;
}

// Obter informações do arquivo
$file_name = basename($requested_file);
$file_size = filesize($requested_file);
$file_type = 'application/pdf';

// Configurar headers para download
header("Content-Description: File Transfer");
header("Content-Type: $file_type");
header("Content-Disposition: attachment; filename=\"$file_name\"");
header("Content-Length: $file_size");
header("Cache-Control: must-revalidate");
header("Pragma: public");
header("Expires: 0");

// Limpar qualquer saída anterior
ob_clean();
flush();

// Ler e enviar o arquivo
readfile($requested_file);
exit;
?>
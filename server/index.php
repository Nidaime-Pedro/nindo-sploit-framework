<?php
session_start();

// Configurações básicas
define('APP_NAME', 'NSF - Nindo Sploit Framework');
define('APP_VERSION', '1.0.0');
define('BASE_PATH', __DIR__);

// Incluir arquivos de configuração
require_once 'config/database.php';

// Verificar se é uma requisição à API
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (strpos($path, '/api/') !== false) {
    // Redirecionar para o endpoint de API correto
    $api_path = substr($path, strpos($path, '/api/') + 5);
    include 'api/' . $api_path . '.php';
    exit;
}

// Incluir cabeçalho
include 'templates/header.php';

// Determinar qual página exibir
$page = $_GET['page'] ?? 'home';

// Verificar autenticação para páginas restritas
$restricted_pages = ['admin', 'profile', 'reports'];

if (in_array($page, $restricted_pages) && !isset($_SESSION['user_id'])) {
    $_SESSION['error'] = 'Você precisa estar logado para acessar esta página.';
    header('Location: index.php?page=login');
    exit;
}

// Carregar a página solicitada
$file = 'views/' . $page . '.php';
if (file_exists($file)) {
    include $file;
} else {
    include 'views/404.php';
}

// Incluir rodapé
include 'templates/footer.php';
?>
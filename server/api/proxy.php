<?php
// Habilitar CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json");

// Para requisições OPTIONS (preflight), retornar apenas os headers
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Configurações da API Flask
$api_url = 'http://localhost:5000/api';

// Obter a rota da API a partir da URL
$request_uri = $_SERVER['REQUEST_URI'];
$uri_parts = explode('/proxy.php/', $request_uri, 2);
$api_route = isset($uri_parts[1]) ? $uri_parts[1] : '';

// Construir a URL completa da API
$full_url = $api_url . '/' . $api_route;

// Obter o corpo da requisição para POST, PUT
$request_body = file_get_contents('php://input');

// Inicializar cURL
$curl = curl_init();

// Configurar opções do cURL
curl_setopt_array($curl, [
    CURLOPT_URL => $full_url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_CUSTOMREQUEST => $_SERVER['REQUEST_METHOD'],
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json'
    ]
]);

// Para métodos POST, PUT com corpo de requisição
if (in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT']) && !empty($request_body)) {
    curl_setopt($curl, CURLOPT_POSTFIELDS, $request_body);
}

// Executar a requisição
$response = curl_exec($curl);
$http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

// Verificar se houve erro na requisição
if ($response === false) {
    $error = curl_error($curl);
    http_response_code(500);
    echo json_encode(['error' => 'Erro na requisição cURL: ' . $error]);
    exit;
}

// Fechar a conexão cURL
curl_close($curl);

// Definir o código HTTP da resposta
http_response_code($http_code);

// Retornar a resposta
echo $response;
?>
<?php
header('Content-Type: application/json');
require_once '../config/database.php';

$db = new Database();
$action = $_GET['action'] ?? '';

// Verificar autenticação para todas as ações exceto download público
if ($action !== 'download') {
    session_start();
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['success' => false, 'message' => 'Authentication required']);
        exit;
    }
}

switch ($action) {
    case 'save':
        saveReport($db);
        break;
    case 'list':
        listReports($db);
        break;
    case 'get':
        getReport($db);
        break;
    case 'download':
        downloadReport($db);
        break;
    case 'delete':
        deleteReport($db);
        break;
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}

function saveReport($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($data['title']) || !isset($data['format']) || !isset($data['content'])) {
        echo json_encode(['success' => false, 'message' => 'Missing required fields']);
        return;
    }
    
    $user_id = $_SESSION['user_id'];
    $file_path = null;
    
    // Se for PDF, salvar em arquivo
    if ($data['format'] === 'pdf' && isset($data['file_path'])) {
        $file_path = $data['file_path'];
        
        // Verificar se o arquivo existe
        if (!file_exists($file_path)) {
            echo json_encode(['success' => false, 'message' => 'PDF file not found']);
            return;
        }
        
        // Mover para diretório permanente se necessário
        $reports_dir = '../reports';
        if (!is_dir($reports_dir)) {
            mkdir($reports_dir, 0755, true);
        }
        
        $new_file_name = 'report_' . time() . '_' . basename($file_path);
        $new_file_path = $reports_dir . '/' . $new_file_name;
        
        if (copy($file_path, $new_file_path)) {
            $file_path = $new_file_path;
        }
    }
    
    $query = "INSERT INTO reports (
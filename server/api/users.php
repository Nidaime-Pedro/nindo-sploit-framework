<?php
header('Content-Type: application/json');
require_once '../config/database.php';

$db = new Database();
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'login':
        handleLogin($db);
        break;
    case 'register':
        handleRegister($db);
        break;
    case 'logout':
        handleLogout();
        break;
    case 'check':
        checkAuth();
        break;
    default:
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        break;
}

function handleLogin($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($data['username']) || !isset($data['password'])) {
        echo json_encode(['success' => false, 'message' => 'Username and password are required']);
        return;
    }
    
    $query = "SELECT * FROM users WHERE username = :username";
    $stmt = $db->executeQuery($query, [':username' => $data['username']]);
    
    if ($stmt && $user = $stmt->fetch(PDO::FETCH_ASSOC)) {
        if (password_verify($data['password'], $user['password'])) {
            // Iniciar sessão
            session_start();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            
            // Remover senha do retorno
            unset($user['password']);
            
            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'user' => $user
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid password']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'User not found']);
    }
}

function handleRegister($db) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validar campos
    $required_fields = ['username', 'email', 'password', 'confirmPassword'];
    foreach ($required_fields as $field) {
        if (!isset($data[$field]) || empty($data[$field])) {
            echo json_encode(['success' => false, 'message' => "Field $field is required"]);
            return;
        }
    }
    
    // Verificar se as senhas coincidem
    if ($data['password'] !== $data['confirmPassword']) {
        echo json_encode(['success' => false, 'message' => 'Passwords do not match']);
        return;
    }
    
    // Verificar se usuário já existe
    $query = "SELECT COUNT(*) FROM users WHERE username = :username OR email = :email";
    $stmt = $db->executeQuery($query, [
        ':username' => $data['username'],
        ':email' => $data['email']
    ]);
    
    if ($stmt && $stmt->fetchColumn() > 0) {
        echo json_encode(['success' => false, 'message' => 'Username or email already exists']);
        return;
    }
    
    // Hash da senha
    $password_hash = password_hash($data['password'], PASSWORD_DEFAULT);
    
    // Inserir novo usuário
    $query = "INSERT INTO users (username, password, email, full_name, role) VALUES (:username, :password, :email, :full_name, 'user')";
    $stmt = $db->executeQuery($query, [
        ':username' => $data['username'],
        ':password' => $password_hash,
        ':email' => $data['email'],
        ':full_name' => $data['username'] // Usando username como nome por simplicidade
    ]);
    
    if ($stmt) {
        echo json_encode(['success' => true, 'message' => 'User registered successfully']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Error registering user']);
    }
}

function handleLogout() {
    session_start();
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Logout successful']);
}

function checkAuth() {
    session_start();
    
    if (isset($_SESSION['user_id'])) {
        $db = new Database();
        $query = "SELECT id, username, email, full_name, role FROM users WHERE id = :id";
        $stmt = $db->executeQuery($query, [':id' => $_SESSION['user_id']]);
        
        if ($stmt && $user = $stmt->fetch(PDO::FETCH_ASSOC)) {
            echo json_encode([
                'authenticated' => true,
                'user' => $user
            ]);
        } else {
            echo json_encode(['authenticated' => false]);
        }
    } else {
        echo json_encode(['authenticated' => false]);
    }
}
?>
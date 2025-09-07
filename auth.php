<?php
require_once 'config.php';

$page = isset($_GET['page']) ? $_GET['page'] : 'login';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        showAlert('Invalid request. Please try again.', 'error');
    } else {
        if ($_POST['action'] === 'login') {
            handleLogin($pdo);
        } elseif ($_POST['action'] === 'register') {
            handleRegister($pdo);
        }
    }
}

function handleLogin($pdo) {
    $email = sanitize($_POST['email']);
    $password = $_POST['password'];
    
    if (empty($email) || empty($password)) {
        showAlert('Please fill in all fields.', 'error');
        return;
    }
    
    if (!validateEmail($email)) {
        showAlert('Please enter a valid email address.', 'error');
        return;
    }
    
    try {
        $stmt = $pdo->prepare("SELECT id, password, first_name, last_name, status FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        
        if ($user && verifyPassword($password, $user['password'])) {
            if ($user['status'] !== 'active') {
                showAlert('Your account is not active. Please contact support.', 'error');
                return;
            }
            
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_name'] = $user['first_name'] . ' ' . $user['last_name'];
            $_SESSION['user_email'] = $email;
            
            // Update last login
            $stmt = $pdo->prepare("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->execute([$user['id']]);
            
            showAlert('Welcome back, ' . $user['first_name'] . '!', 'success');
            header('Location: dashboard.php');
            exit();
        } else {
            showAlert('Invalid email or password.', 'error');
        }
    } catch (PDOException $e) {
        showAlert('Login failed. Please try again.', 'error');
        error_log($e->getMessage());
    }
}

function handleRegister($pdo) {
    $first_name = sanitize($_POST['first_name']);
    $last_name = sanitize($_POST['last_name']);
    $email = sanitize($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $phone = sanitize($_POST['phone']);
    
    // Validation
    if (empty($first_name) || empty($last_name) || empty($email) || empty($password)) {
        showAlert('Please fill in all required fields.', 'error');
        return;
    }
    
    if (!validateEmail($email)) {
        showAlert('Please enter a valid email address.', 'error');
        return;
    }
    
    if (strlen($password) < 6) {
        showAlert('Password must be at least 6 characters long.', 'error');
        return;
    }
    
    if ($password !== $confirm_password) {
        showAlert('Passwords do not match.', 'error');
        return;
    }
    
    try {
        // Check if email already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            showAlert('Email address is already registered.', 'error');
            return;
        }
        
        // Create new user
        $hashed_password = hashPassword($password);
        $stmt = $pdo->prepare("\n            INSERT INTO users (first_name, last_name, email, password, phone) \n            VALUES (?, ?, ?, ?, ?)\n        ");
        $stmt->execute([$first_name, $last_name, $email, $hashed_password, $phone]);
        
        $user_id = $pdo->lastInsertId();
        
        // Also create a members record so admins can see new registrations
        // Use the mysqli connection helper from config.php to avoid mixing PDO vs mysqli usage
        $conn = getConnection();
        if ($conn) {
            try {
                $membership_plan = 'basic';
                $start_date = date('Y-m-d');
                $membership_duration = 12; // default 12 months
                $status = 'active';

                $memberStmt = $conn->prepare(
                    "INSERT INTO members (first_name, last_name, email, phone, membership_plan, start_date, membership_duration, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())"
                );
                if ($memberStmt) {
                    // types: first_name(s), last_name(s), email(s), phone(s), membership_plan(s), start_date(s), membership_duration(i), status(s)
                    $memberStmt->bind_param('ssssssis', $first_name, $last_name, $email, $phone, $membership_plan, $start_date, $membership_duration, $status);
                    $memberStmt->execute();
                    $memberStmt->close();
                } else {
                    error_log('Failed to prepare members insert: ' . $conn->error);
                }
            } catch (Exception $e) {
                error_log('Failed to create member record: ' . $e->getMessage());
            } finally {
                $conn->close();
            }
        } else {
            error_log('Could not establish mysqli connection to insert member record');
        }
        
        // Auto-login after registration
        $_SESSION['user_id'] = $user_id;
        $_SESSION['user_name'] = $first_name . ' ' . $last_name;
        $_SESSION['user_email'] = $email;
        
        showAlert('Registration successful! Welcome to FitForge, ' . $first_name . '!', 'success');
        header('Location: dashboard.php');
        exit();
        
    } catch (PDOException $e) {
        showAlert('Registration failed. Please try again.', 'error');
        error_log($e->getMessage());
    }
}

redirectIfLoggedIn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $page === 'register' ? 'Register' : 'Login'; ?> - FitForge Gym</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;600;700;800&family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link rel="stylesheet" href="auth-styles.css">
</head>
<body>
    <div class="auth-container">
        <!-- Background Elements -->
        <div class="bg-elements">
            <div class="bg-circle bg-circle-1"></div>
            <div class="bg-circle bg-circle-2"></div>
            <div class="bg-circle bg-circle-3"></div>
        </div>
        
        <!-- Navigation -->
        <div class="auth-nav">
            <div class="logo">
                <h2><i class="fas fa-dumbbell"></i> FitForge</h2>
            </div>
            <div class="nav-links">
                <a href="../Gym/index.php" class="back-home">
                    <i class="fas fa-arrow-left"></i> Back to Home
                </a>
            </div>
        </div>
        
        <!-- Auth Form Container -->
        <div class="auth-form-container">
            <div class="auth-form-wrapper">
                <!-- Form Toggle -->
                <div class="form-toggle">
                    <button class="toggle-btn <?php echo $page === 'login' ? 'active' : ''; ?>" 
                            onclick="switchForm('login')">Login</button>
                    <button class="toggle-btn <?php echo $page === 'register' ? 'active' : ''; ?>" 
                            onclick="switchForm('register')">Register</button>
                </div>
                
                <?php 
                $alert = getAlert();
                if ($alert): 
                ?>
                <div class="alert alert-<?php echo $alert['type']; ?>">
                    <i class="fas fa-<?php echo $alert['type'] === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                    <?php echo htmlspecialchars($alert['message']); ?>
                </div>
                <?php endif; ?>
                
                <!-- Login Form -->
                <form id="loginForm" class="auth-form <?php echo $page === 'login' ? 'active' : ''; ?>" 
                      method="POST" action="?page=login">
                    <input type="hidden" name="action" value="login">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    
                    <div class="form-header">
                        <h3>Welcome Back</h3>
                        <p>Sign in to your FitForge account</p>
                    </div>
                    
                    <div class="form-group">
                        <div class="input-wrapper">
                            <i class="fas fa-envelope"></i>
                            <input type="email" name="email" placeholder="Email Address" required 
                                   value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="input-wrapper">
                            <i class="fas fa-lock"></i>
                            <input type="password" name="password" placeholder="Password" required>
                            <button type="button" class="toggle-password" onclick="togglePassword(this)">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="form-options">
                        <label class="remember-me">
                            <input type="checkbox" name="remember">
                            <span class="checkmark"></span>
                            Remember me
                        </label>
                        <a href="#" class="forgot-password">Forgot Password?</a>
                    </div>
                    
                    <button type="submit" class="auth-btn">
                        <i class="fas fa-sign-in-alt"></i>
                        Sign In
                    </button>
                    
                    <div class="form-footer">
                        <p>Don't have an account? 
                           <a href="#" onclick="switchForm('register')">Sign up here</a>
                        </p>
                    </div>
                </form>
                
                <!-- Register Form -->
                <form id="registerForm" class="auth-form <?php echo $page === 'register' ? 'active' : ''; ?>" 
                      method="POST" action="?page=register">
                    <input type="hidden" name="action" value="register">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    
                    <div class="form-header">
                        <h3>Join FitForge</h3>
                        <p>Create your account and start your fitness journey</p>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <div class="input-wrapper">
                                <i class="fas fa-user"></i>
                                <input type="text" name="first_name" placeholder="First Name" required
                                       value="<?php echo isset($_POST['first_name']) ? htmlspecialchars($_POST['first_name']) : ''; ?>">
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <div class="input-wrapper">
                                <i class="fas fa-user"></i>
                                <input type="text" name="last_name" placeholder="Last Name" required
                                       value="<?php echo isset($_POST['last_name']) ? htmlspecialchars($_POST['last_name']) : ''; ?>">
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="input-wrapper">
                            <i class="fas fa-envelope"></i>
                            <input type="email" name="email" placeholder="Email Address" required
                                   value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="input-wrapper">
                            <i class="fas fa-phone"></i>
                            <input type="tel" name="phone" placeholder="Phone Number (Optional)"
                                   value="<?php echo isset($_POST['phone']) ? htmlspecialchars($_POST['phone']) : ''; ?>">
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <div class="input-wrapper">
                                <i class="fas fa-lock"></i>
                                <input type="password" name="password" placeholder="Password" required>
                                <button type="button" class="toggle-password" onclick="togglePassword(this)">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <div class="input-wrapper">
                                <i class="fas fa-lock"></i>
                                <input type="password" name="confirm_password" placeholder="Confirm Password" required>
                                <button type="button" class="toggle-password" onclick="togglePassword(this)">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="terms-agreement">
                            <input type="checkbox" name="terms" required>
                            <span class="checkmark"></span>
                            I agree to the <a href="#" target="_blank">Terms of Service</a> and 
                            <a href="#" target="_blank">Privacy Policy</a>
                        </label>
                    </div>
                    
                    <button type="submit" class="auth-btn">
                        <i class="fas fa-user-plus"></i>
                        Create Account
                    </button>
                    
                    <div class="form-footer">
                        <p>Already have an account? 
                           <a href="#" onclick="switchForm('login')">Sign in here</a>
                        </p>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <script src="auth-script.js"></script>
</body>
</html>

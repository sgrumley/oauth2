package main

const homeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Redirect Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1, h2 {
            color: #2c3e50;
        }
        .btn {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            border-radius: 4px;
            text-decoration: none;
            margin: 10px 0;
            cursor: pointer;
            border: none;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        pre {
            background-color: #f1f1f1;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .form-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth Redirect Flow Demo</h1>
        <p>This demo shows the OAuth 2.0 redirect flow.</p>
        
        <h2>Login</h2>
        <form id="loginForm" method="post" action="/submit-login">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
    </div>
</body>
</html>`

const successHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #2c3e50;
        }
        .success-icon {
            color: #2ecc71;
            font-size: 48px;
            text-align: center;
            margin: 20px 0;
        }
        .btn {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            border-radius: 4px;
            text-decoration: none;
            margin: 10px 0;
            cursor: pointer;
        }
        .btn:hover {
            background-color: #2980b9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login Successful</h1>
        
        <div class="success-icon">✓</div>
        
        <p>You have successfully logged in.</p>
        
        <a href="/" class="btn">Return to Home</a>
    </div>
</body>
</html>`

const errorHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Error</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #e74c3c;
        }
        .error-icon {
            color: #e74c3c;
            font-size: 48px;
            text-align: center;
            margin: 20px 0;
        }
        .btn {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            border-radius: 4px;
            text-decoration: none;
            margin: 10px 0;
            cursor: pointer;
        }
        .btn:hover {
            background-color: #2980b9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login Error</h1>
        
        <div class="error-icon">✗</div>
        
        <p>An error occurred during login: %s</p>
        
        <a href="/" class="btn">Try Again</a>
    </div>
</body>
</html>`

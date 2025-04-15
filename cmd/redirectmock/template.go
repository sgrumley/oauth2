package main

// HTML templates
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
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth Redirect Flow Demo</h1>
        <p>This demo shows the OAuth 2.0 redirect flow.</p>
        
        <h2>How it works:</h2>
        <ol>
            <li>Click the login button below (to mock entering a username and password)</li>
            <li>You'll be redirected to the authorization server</li>
            <li>After authorization, you'll be redirected back with a code</li>
            <li>The code will be displayed on the callback page</li>
        </ol>
        
        <a href="/login" class="btn">Login with OAuth</a>
    </div>
</body>
</html>`

const callbackSuccessHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Callback</title>
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
        .url-bar {
            background-color: #eee;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
            margin: 10px 0;
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
        .params {
            background-color: #f8f9fa;
            padding: 10px;
            border-left: 3px solid #3498db;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth Callback Received</h1>
        
        <div class="success-icon">✓</div>
        
        <h2>Callback URL</h2>
        <div class="url-bar">%s</div>
        
        <h2>Authorization Code</h2>
        <div class="params">
            <p><strong>code:</strong> %s</p>
            <p><strong>state:</strong> %s</p>
        </div>
        
        <h2>Next Steps</h2>
        <p>In a real OAuth implementation, the application would now:</p>
        <ol>
            <li>Exchange this authorization code for an access token</li>
            <li>Use the access token to make API requests</li>
            <li>Refresh the token when it expires</li>
        </ol>
        
        <a href="/" class="btn">Start Over</a>
    </div>
</body>
</html>`

const callbackErrorHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Error</title>
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
        <h1>OAuth Authorization Error</h1>
        
        <div class="error-icon">✗</div>
        
        <h2>Error Details</h2>
        <p><strong>Error:</strong> %s</p>
        <p><strong>Description:</strong> %s</p>
        
        <a href="/" class="btn">Try Again</a>
    </div>
</body>
</html>`

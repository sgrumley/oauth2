document.addEventListener("DOMContentLoaded", function () {
  const loginBtn = document.getElementById("loginBtn");
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");
  const statusMessage = document.getElementById("statusMessage");

  loginBtn.addEventListener("click", async function () {
    // Reset status message
    statusMessage.style.display = "none";
    statusMessage.className = "status-message";

    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();
    const validationResult = validateCredentials(username, password);

    if (validationResult.valid) {
      // Disable button during login process
      loginBtn.disabled = true;
      loginBtn.textContent = "Logging in...";

      // Second call: Attempt login (now async)
      const loginResult = await attemptLogin(username, password);

      // Reset button
      loginBtn.disabled = false;
      loginBtn.textContent = "Login";

      // Display result message
      statusMessage.textContent = loginResult.message;
      statusMessage.classList.add(
        loginResult.success ? "status-success" : "status-error",
      );
      statusMessage.style.display = "block";

      // If login was successful, call the callback function
      if (loginResult.success) {
        // Make callback request
        const callbackResult = await callback();
        console.log("Callback result:", callbackResult);

        // You can handle the callback result here if needed
        if (callbackResult.success) {
          // Can add additional handling for successful callback
          console.log("Callback successful");
        } else {
          // Handle failed callback
          console.warn("Callback failed:", callbackResult.message);
        }
      }
    } else {
      // Display validation error
      statusMessage.textContent = validationResult.message;
      statusMessage.classList.add("status-error");
      statusMessage.style.display = "block";
    }
  });

  // First function call: Validate credentials
  function validateCredentials(username, password) {
    console.log("Validating credentials...");
    if (!username) {
      return {
        valid: false,
        message: "Username is required",
      };
    }
    if (!password) {
      return {
        valid: false,
        message: "Password is required",
      };
    }
    return {
      valid: true,
      message: "Validation successful",
    };
  }

  async function attemptLogin(username, password) {
    console.log("Attempting login...");
    try {
      const response = await fetch("http://localhost:8082/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });
      // Parse the JSON response
      const data = await response.json();
      // Return the response data
      return {
        success: data.success,
        message:
          data.message ||
          (data.success
            ? "Login successful! Redirecting..."
            : "Invalid username or password"),
      };
    } catch (error) {
      console.error("Login error:", error);
      return {
        success: false,
        message: "Error connecting to the server. Please try again.",
      };
    }
  }

  async function callback() {
    console.log("Attempting callback...");
    try {
      // Get state from current URL
      const params = new URLSearchParams(window.location.search);
      const state = params.get("state");

      // Build the callback URL, adding state if it exists
      let url = "http://localhost:8082/callback";
      if (state) {
        url += `?state=${encodeURIComponent(state)}`;
      }

      const response = await fetch(url, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });
      // Parse the JSON response
      const data = await response.json();
      // Return the response data
      return {
        success: data.success,
        message: data.message || "Callback completed",
      };
    } catch (error) {
      console.error("Callback error:", error);
      return {
        success: false,
        message: "Error during callback. Please try again.",
      };
    }
  }
});

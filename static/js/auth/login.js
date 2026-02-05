// login.js

// ------------- Helper functions for loading spinner -------------
function setLoading(button, text = "Processing...") {
    button.disabled = true;
    button.originalText = button.innerHTML;
    button.innerHTML = `
        <span class="spinner"></span> ${text}
    `;
}



// ------------- Modal popup for success -------------
function showSuccessModal(message, redirectUrl = null, delay = 0) {
    // Overlay
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    // Modal
    const modal = document.createElement("div");
    modal.className = "modal-card";

    modal.innerHTML = `
        <div class="modal-icon">
            <svg viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                <path d="M8 12.5l2.5 2.5L16 9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        </div>

        <h2>Success</h2>
        <p>${message}</p>

        <button class="modal-btn">Continue</button>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Trigger animation
    requestAnimationFrame(() => overlay.classList.add("show"));

    const closeModal = () => {
        overlay.classList.remove("show");
        setTimeout(() => overlay.remove(), 250);
    };

    // Button click
    modal.querySelector(".modal-btn").onclick = () => {
        closeModal();
        if (redirectUrl) window.location.href = redirectUrl;
    };

    // Click outside to close
    overlay.onclick = (e) => {
        if (e.target === overlay) closeModal();
    };

    // Escape key
    document.addEventListener("keydown", function escClose(e) {
        if (e.key === "Escape") {
            closeModal();
            document.removeEventListener("keydown", escClose);
        }
    });

    // Auto redirect
    if (redirectUrl && delay > 0) {
        setTimeout(() => {
            closeModal();
            window.location.href = redirectUrl;
        }, delay);
    }
}


function showErrorModal(message) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    const modal = document.createElement("div");
    modal.className = "modal-card error";

    modal.innerHTML = `
        <div class="modal-icon error-icon">
            <svg viewBox="0 0 24 24" fill="none">
                <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                <path d="M15 9l-6 6M9 9l6 6"
                      stroke="currentColor"
                      stroke-width="2"
                      stroke-linecap="round"/>
            </svg>
        </div>

        <h2>Error</h2>
        <p>${message}</p>

        <button class="modal-btn error-btn">Close</button>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    requestAnimationFrame(() => overlay.classList.add("show"));

    const close = () => {
        overlay.classList.remove("show");
        setTimeout(() => overlay.remove(), 250);
    };

    modal.querySelector(".error-btn").onclick = close;

    overlay.onclick = (e) => {
        if (e.target === overlay) close();
    };

    document.addEventListener("keydown", function esc(e) {
        if (e.key === "Escape") {
            close();
            document.removeEventListener("keydown", esc);
        }
    });
}
// ------------- Spinner CSS dynamically (optional) -------------
const style = document.createElement("style");
style.innerHTML = `
.spinner {
    border: 3px solid rgba(255,255,255,0.3);
    border-top: 3px solid #fff;
    border-radius: 50%;
    width: 18px;
    height: 18px;
    display: inline-block;
    margin-right: 8px;
    animation: spin 0.8s linear infinite;
}
@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
`;
document.head.appendChild(style);

// ------------- Grab form and button -------------
const loginForm = document.getElementById("loginForm");
const loginBtn = document.getElementById("SigninButton");
const resetForm = document.getElementById("resetForm");
const resetBtn = document.getElementById("resetPassword");
const saveForm = document.getElementById("passwordForm");
const saveBtn = document.getElementById("savePassword");
const restBtna = document.getElementById("resetpsbtn");
const logindiv = document.getElementById("login");
const resetdiv = document.getElementById("reset-password");
const savediv = document.getElementById("save-password");

function clearLoading(button) {
    button.disabled = false;
    button.innerHTML = button.originalText;
}

function showOnly(div) {
    logindiv.style.display = "none";
    resetdiv.style.display = "none";
    savediv.style.display = "none";

    div.style.display = "block";
}


// ------------- Submit event -------------
loginForm.addEventListener("submit", async function(e) {
    e.preventDefault();

    const username = document.getElementById("username_input").value.trim();
    const password = document.getElementById("password_input").value.trim();

    if (!username || !password) {
        showErrorModal("Please enter both username and password.");
        return;
    }

    setLoading(loginBtn, "Logging in...");

    const payload = { username, password };

    try {
        const response = await fetch("/loginp", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const data = await response.json();
        console.log("Login response:", data);

        clearLoading(loginBtn);

        if (data.status === "success") {
            showSuccessModal("Login successful!", "/dashboard", 2000);
        } else {
            showErrorModal(data.message || "Login failed");
        }

    } catch (error) {
        clearLoading(loginBtn);
        console.error("Error:", error);
        showErrorModal("An error occurred during login");
    }
});

restBtna.addEventListener('click', function () {
  logindiv.style.display = 'none';
  resetdiv.style.display = 'block';
});


resetForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const security_question = document.getElementById("security_question_input").value;
    const security_answer = document.getElementById("security_answer_input").value;
    if (!security_question || !security_answer) {
        showErrorModal("Please enter both security question and answer");
        return;
    }


    setLoading(resetBtn, "Reseting......");

    const d_dict = {
        username: document.getElementById("username_input").value,
        security_question: security_question, 
        security_answer: security_answer
    };

    try {
        const response = await fetch("/resetpass", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(d_dict)
        });

        const data = await response.json();
        console.log("Reset response:", data);

        clearLoading(resetBtn);

        if (data.status === "success") {
            showOnly(savediv);
        } else {
            showErrorModal(data.message || "Reset failed");
        }

    } catch (error) {
        clearLoading(resetBtn);
        console.error("Error:", error);
        showErrorModal("An error occurred during Reset");
    }
});

saveForm.addEventListener('submit', async function (e) {
    e.preventDefault();

    const entered_code = document.getElementById("verification_code_input").value;
    const password = document.getElementById("password_input_reset").value;
    const confirmpassowrd = document.getElementById("confirm_password_input").value;

    if (!entered_code || !password || !confirmpassowrd) {
        showErrorModal("All fields are required.");
        return;
    }  
    if (password !== confirmpassowrd) {
        showErrorModal("Passowrds doesn't match");
        return;
    }

    setLoading(saveBtn, "Saving Passowrd....");
    const d_dict = {
        username:document.getElementById("username_input").value,
        reset_code: document.getElementById("verification_code_input").value, 
        new_password: password,
    };

    console.log("DATA -", d_dict)

    
    try {
        const response = await fetch("/save-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(d_dict)
        });

        const data = await response.json();
        console.log("Save response:", data);

        clearLoading(saveBtn);

        if (data.status === "success") {
            showSuccessModal("Password reset successfully. You can login now", "/login",3000);
        } else {
            showErrorModal(data.message || "Save failed");
        }

    } catch (error) {
        clearLoading(saveBtn);
        console.error("Error:", error);
        showErrorModal("An error occurred during Reset");
    }



});

async function faceidLogin() {
    const username = document.getElementById("username_input").value;

    let res = await fetch("/webauthn/auth/options", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ username })
    });
    const options = await res.json();

    options.challenge = Uint8Array.from(atob(options.challenge), c=>c.charCodeAt(0));
    options.allowCredentials.forEach(c => {
        c.id = Uint8Array.from(atob(c.id), d=>d.charCodeAt(0));
    });

    const credential = await navigator.credentials.get({ publicKey: options });

    const data = {
        username,
        id: credential.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
        response: {
            authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
            signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
            userHandle: credential.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
        },
        type: credential.type
    };

    await fetch("/webauthn/auth/verify", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify(data)
    });

    window.location.href = "/dashboard";
}

document.getElementById("faceid-login")
    .addEventListener("click", faceidLogin);
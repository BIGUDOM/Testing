/* ================= DIVS ================= */
const userDiv = document.getElementById("userbase");
const custDiv = document.getElementById("custbase");
const verifyDiv = document.getElementById("verify");
const completeCustDiv = document.getElementById("completecust");
const scrollIndicator = document.getElementById("scrollIndicator");

/* ================= FORMS ================= */
const userForm = document.getElementById("userForm");
const custForm = document.getElementById("custForm");
const verifyForm = document.getElementById("verifyForm");
const completeCustForm = document.getElementById("completecustform");

/* ================= BUTTONS ================= */
const resendCodeBtn = document.getElementById("resend_code_btn");

/* ================= HELPERS ================= */
function showOnly(div) {
    userDiv.style.display = "none";
    custDiv.style.display = "none";
    verifyDiv.style.display = "none";
    completeCustDiv.style.display = "none";

    div.style.display = "block";
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

// -------------------------
// Loading Spinner Helpers
// -------------------------

function setLoading(button, text = "Loading...") {
    button.dataset.originalText = button.innerHTML;
    button.disabled = true;

    // Add spinner HTML (simple rolling dots)
    button.innerHTML = `
        <span class="spinner"></span> ${text}
    `;
}

function clearLoading(button) {
    button.innerHTML = button.dataset.originalText || "Submit";
    button.disabled = false;
}


const code = String(Math.floor(100000 + Math.random()*900000));
/* ================= USER REGISTRATION (FIRST SCREEN) ================= */
userForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const submitBtn = document.getElementById("userNextButton");

    const data = {
        username: document.getElementById("username_input").value.trim(),
        email: document.getElementById("email_input").value.trim(),
        password: document.getElementById("password_input").value,
        confirm_password: document.getElementById("confirm_password_input").value,
        security_question: document.getElementById("security_question_input").value.trim(),
        security_answer: document.getElementById("security_answer_input").value.trim(),
        verification_code: code
    };

    console.log("USER FORM DATA →", data);

    // VALIDATION
    if (!data.username || !data.email || !data.security_question || !data.security_answer) {
        showErrorModal("All fields are required.");
        return;
    }
    if (data.password !== data.confirm_password) {
        showErrorModal("Passwords don't match");
        return;
    }

    setLoading(submitBtn, "Creating account...");

    try {
        const response = await fetch("/user", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        console.log("USER FORM RESPONSE →", result);
        clearLoading(submitBtn);

        if (result.status === "success") {
            showOnly(verifyDiv);
            verifyDiv.classList.add("active");
        } else {
            showErrorModal(result.message || "Registration failed");
        }
    } catch (err) {
        clearLoading(submitBtn);
        console.error("USER FORM ERROR →", err);
        showErrorModal("Server error");
    }
});


/* ================= VERIFY EMAIL ================= */
verifyForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const verifyBtn = document.getElementById("verifyButton");
    const enteredcode = document.getElementById("verification_code_input").value;

    if (!enteredcode) { 
        showErrorModal("Enter the code you recieved.");
        return;
    }

    console.log("VERIFY CODE →", code);
    setLoading(verifyBtn, "Verifying...");

    const data = {
        generated_code: code,
        verification_code: enteredcode
    };
    try {
        const response = await fetch("/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        console.log("VERIFY FORM RESPONSE →", result);
        clearLoading(verifyBtn);

        if (result.status === "success") {
            showOnly(custDiv);
            custDiv.classList.add("active")
        } else {
            showErrorModal(result.message || "Verification failed");
        }
    } catch (err) {
        clearLoading(verifyBtn);
        console.error("VERIFY FORM ERROR →", err);
        showErrorModal("Server error");
    }
});

/* ================= RESEND CODE ================= */
resendCodeBtn.addEventListener("click",async function () {
    console.log("Resending verification code...");

    const data = {
        email: document.getElementById("email_input").value,
        verification_code: code
    };
    setLoading(resendCodeBtn, "Resending code...")
    try {
        const response = await fetch("/resend", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        console.log("VERIFY FORM RESPONSE →", result);
        clearLoading(resendCodeBtn);

        if (result.status === "success") {
            showOnly(custDiv);
            custDiv.classList.add("active")
        } else {
            showErrorModal(result.message || "Verification failed");
        }
    } catch (err) {
        clearLoading(resendCodeBtn);
        console.error("VERIFY FORM ERROR →", err);
        showErrorModal("Server error");
    }
});

/* ================= CREATE PROFILE ================= */
custForm.addEventListener("submit", async function (e) {
    e.preventDefault();

    const submitBtn = document.getElementById("custNextButton");

    const data = {
        username: document.getElementById("username_input").value,
        profile_name: document.getElementById("profile_name_input").value,
        full_name: document.getElementById("full_name_input").value,
        address: document.getElementById("address_input").value,
        country: document.getElementById("country_input").value,
        currency: document.getElementById("currency_input").value,
        dob: document.getElementById("dob_input").value,
    };

    if (!data.profile_name || !data.full_name || !data.address || !data.country || !data.currency || !data.dob){
        showErrorModal("All fields required.");
        return;
    }
    console.log("CREATE PROFILE DATA →", data);
    setLoading(submitBtn, "Saving profile...");

    try {
        const response = await fetch("/cust", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        console.log("CUST FORM RESPONSE →", result);
        clearLoading(submitBtn);

        if (result.status === "success") {

            showOnly(completeCustDiv);
            completeCustDiv.classList.add("active")
        } else {
            showErrorModal(result.message || "Saving Profile failed");
        }
    } catch (err) {
        clearLoading(submitBtn);
        console.error("Cust FORM ERROR →", err);
        showErrorModal("Server error");
    }
});



const enablefaceBtn = document.getElementById("enableFaceID");
// Helper: base64url -> ArrayBuffer
function base64urlToArrayBuffer(base64url) {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const str = atob(base64);
    const buffer = new ArrayBuffer(str.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) view[i] = str.charCodeAt(i);
    return buffer;
}

// Helper: ArrayBuffer -> base64url
function arrayBufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (let i = 0; i < bytes.byteLength; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const enableFaceBtn = document.getElementById("enableFaceID");
enableFaceBtn.addEventListener("click", async () => {
    const username = document.getElementById("username_input").value;

    // 1️⃣ Get registration options from server
    const res = await fetch('/passkey/register/options', {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username })
    });
    const options = await res.json();

    // 2️⃣ Convert challenge & user.id to ArrayBuffer
    options.challenge = base64urlToArrayBuffer(options.challenge);
    options.user.id = base64urlToArrayBuffer(options.user.id);

    if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(c => ({
            ...c,
            id: base64urlToArrayBuffer(c.id)
        }));
    }

    // 3️⃣ Call WebAuthn API
    const cred = await navigator.credentials.create({ publicKey: options });

    // 4️⃣ Convert ArrayBuffers to base64url for sending
    const credData = {
        id: cred.id,
        type: cred.type,
        rawId: arrayBufferToBase64url(cred.rawId),
        response: {
            clientDataJSON: arrayBufferToBase64url(cred.response.clientDataJSON),
            attestationObject: arrayBufferToBase64url(cred.response.attestationObject)
        },
        username  // include username for server
    };

    // 5️⃣ Send credential to server for verification
    const verifyRes = await fetch("/passkey/register/verify", {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credData)
    });
    const result = await verifyRes.json();

    if (result.status === "ok") {
        alert("Face ID / Passkey enabled!");
    } else {
        console.error(result);
        alert("Registration failed: " + (result.error || "Unknown error"));
    }
});

// enablefaceBtn.addEventListener("click", async () => {
//     const res = await fetch('/passkey/register/options', {
//         method: 'POST',
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({username : document.getElementById("username_input").value })
//     });

//     const options = await res.json();
//     options.challenge = base64urlToArrayBuffer(options.challenge);
//     options.user.id   = base64urlToArrayBuffer(options.user.id);

//     if (options.excludeCredentials) {
//         options.excludeCredentials = options.excludeCredentials.map(c => ({
//             ...c,
//          id: base64urlToArrayBuffer(c.id)
//         }));
//     }


// const cred = await navigator.credentials.create({
//     publicKey: options
// });



//     const data = await fetch("/passkey/register/verfiy", {
//         method: 'POST',
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify(cred)
//     });
//     const result = await data.json();
//     if (result.status === "ok") {
//         showSuccessModal("Face ID enabled!");
//     }

 
// });

/* ================= COMPLETE PROFILE ================= */
completeCustForm.addEventListener("submit", async function(e) {
    e.preventDefault();

    // Collect form data
    const formData = new FormData(completeCustForm);
    const completeCustButton = document.getElementById("completeCustButton");

    // Optional: Add username/email from previous step if not in this form
    const usernameInput = document.getElementById("username_input");
    const emailInput = document.getElementById("email_input");

    if (usernameInput) formData.append("username", usernameInput.value.trim());
    if (emailInput) formData.append("email", emailInput.value.trim());
    
    

    // Assign missing fields manually
    formData.set("username", document.getElementById("username_input").value);
    formData.set("email", document.getElementById("email_input").value);
    formData.set("profile_name", document.getElementById("profile_name_input").value); 
    // Simple validation
    const requiredFields = [ "profile_name", "phone_number", "alternate_email", "website", "bio"];
    for (let field of requiredFields) {
        if (!formData.get(field) || formData.get(field).trim() === "") {
            showErrorModal(`Field "${field}" is required.`);
            return;
        }
    }

    console.log("Submitting Complete Customer Form...");
    for (let [key, value] of formData.entries()) {
        console.log(key, value);
    }

    // Set loading
    setLoading(completeCustButton, "Completing Profile...");

    try {
        const response = await fetch("/completecust", {
            method: "POST",
            body: formData
        });

        const data = await response.json();
        console.log("Response:", data);

        if (data.status === "success") {
            showSuccessModal("Profile Completed. You can login now and start.", "/login", 2000)

        } else {
            clearLoading(completeCustButton);
            showErrorModal(data.message || "Failed to complete profile");
        }

    } catch (error) {
        clearLoading(completeCustButton);
        console.error("Error completing profile:", error);
        showErrorModal("An error occurred while completing your profile.");
    }
    /* ---------- SCROLL TO TOP ---------- */
    window.addEventListener("scroll", () => {
        scrollIndicator?.classList.toggle("visible", window.scrollY > 300);
    });

    scrollIndicator?.addEventListener("click", () => {
        window.scrollTo({ top: 0, behavior: "smooth" });
    });
});

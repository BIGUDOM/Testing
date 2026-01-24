// dashboard.js

// ---------- Helper Functions ----------
function setLoading(button, text = "Processing...") {
    button.disabled = true;
    button.originalText = button.innerHTML;
    button.innerHTML = `<span class="spinner"></span> ${text}`;
}

function clearLoading(button) {
    button.disabled = false;
    button.innerHTML = button.originalText;
}

function showOnly(div) {
    userDiv.style.display = "none";
    custDiv.style.display = "none";
    verifyDiv.style.display = "none";
    completeCustDiv.style.display = "none";
    completedDiv.style.display = "none";

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

// Spinner CSS
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

// ---------- Grab Elements ----------
const showInvoiceBtn = document.getElementById("show-invoice-btn");
const viewInvoicesBtn = document.querySelector(".btn.secondary");

// ---------- Button Events ----------
if (showInvoiceBtn) {
    showInvoiceBtn.addEventListener("click", (e) => {
        e.preventDefault();
        setLoading(showInvoiceBtn, "Opening Invoice...");
        // Redirect after small delay for spinner effect
        setTimeout(() => {
            clearLoading(showInvoiceBtn);
            window.location.href = "/create/invoice";
        }, 500);
    });
}

if (viewInvoicesBtn) {
    viewInvoicesBtn.addEventListener("click", (e) => {
        e.preventDefault();
        setLoading(viewInvoicesBtn, "Loading Invoices...");
        setTimeout(() => {
            clearLoading(viewInvoicesBtn);
            window.location.href = "/invoices";
        }, 500);
    });
}

// ---------- Optional: Dynamic greeting ----------
// dashboard.js

document.addEventListener("DOMContentLoaded", () => {
    const greetingText = document.getElementById("greeting-text");
    const usernamePlaceholder = document.getElementById("username-placeholder");

    if (greetingText && usernamePlaceholder) {
        const now = new Date();
        const hour = now.getHours();
        let timeGreeting = "Welcome back";

        if (hour < 12) timeGreeting = "Good morning";
        else if (hour < 18) timeGreeting = "Good afternoon";
        else timeGreeting = "Good evening";

        // Use the username injected by Flask
        const username = usernamePlaceholder.textContent || "";
        greetingText.innerHTML = `${timeGreeting}, ${username} 👋`;
    }
});




document.addEventListener('DOMContentLoaded', function() {
      const header = document.querySelector('header');
      const navUl = header.querySelector('aside');
      // Create toggle button
      const btn = document.createElement('button');
      btn.className = 'nav-toggle';
      btn.setAttribute('aria-label', 'Toggle navigation');
      btn.innerHTML = '&#9776;';
      nav.insertBefore(btn, navUl);
      btn.addEventListener('click', function() {
        navUl.classList.toggle('open');
      });
      // Close menu on link click (mobile)
      navUl.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', function() {
          if(window.innerWidth <= 700) navUl.classList.remove('open');
        });
      });
    });

const toggle = document.getElementById('menuToggle');
const sidebar = document.getElementById('sidebar');
const overlay = document.getElementById('sidebarOverlay');

toggle.addEventListener('click', () => {
    sidebar.classList.add('open');
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';
});

overlay.addEventListener('click', closeSidebar);

function closeSidebar() {
    sidebar.classList.remove('open');
    overlay.classList.remove('active');
    document.body.style.overflow = '';
}

// Close on resize to desktop
window.addEventListener('resize', () => {
    if (window.innerWidth >= 1024) {
        closeSidebar();
    }
});

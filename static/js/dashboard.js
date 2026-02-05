// // dashboard.js

// // ---------- Helper Functions ----------
// function setLoading(button, text = "Processing...") {
//     button.disabled = true;
//     button.originalText = button.innerHTML;
//     button.innerHTML = `<span class="spinner"></span> ${text}`;
// }

// function clearLoading(button) {
//     button.disabled = false;
//     button.innerHTML = button.originalText;
// }

// function showOnly(div) {
//     userDiv.style.display = "none";
//     custDiv.style.display = "none";
//     verifyDiv.style.display = "none";
//     completeCustDiv.style.display = "none";
//     completedDiv.style.display = "none";

//     div.style.display = "block";
// }

// // ------------- Modal popup for success -------------
// function showSuccessModal(message, redirectUrl = null, delay = 0) {
//     // Overlay
//     const overlay = document.createElement("div");
//     overlay.className = "modal-overlay";

//     // Modal
//     const modal = document.createElement("div");
//     modal.className = "modal-card";

//     modal.innerHTML = `
//         <div class="modal-icon">
//             <svg viewBox="0 0 24 24" fill="none">
//                 <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
//                 <path d="M8 12.5l2.5 2.5L16 9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
//             </svg>
//         </div>

//         <h2>Success</h2>
//         <p>${message}</p>

//         <button class="modal-btn">Continue</button>
//     `;

//     overlay.appendChild(modal);
//     document.body.appendChild(overlay);

//     // Trigger animation
//     requestAnimationFrame(() => overlay.classList.add("show"));

//     const closeModal = () => {
//         overlay.classList.remove("show");
//         setTimeout(() => overlay.remove(), 250);
//     };

//     // Button click
//     modal.querySelector(".modal-btn").onclick = () => {
//         closeModal();
//         if (redirectUrl) window.location.href = redirectUrl;
//     };

//     // Click outside to close
//     overlay.onclick = (e) => {
//         if (e.target === overlay) closeModal();
//     };

//     // Escape key
//     document.addEventListener("keydown", function escClose(e) {
//         if (e.key === "Escape") {
//             closeModal();
//             document.removeEventListener("keydown", escClose);
//         }
//     });

//     // Auto redirect
//     if (redirectUrl && delay > 0) {
//         setTimeout(() => {
//             closeModal();
//             window.location.href = redirectUrl;
//         }, delay);
//     }
// }

// function showErrorModal(message) {
//     const overlay = document.createElement("div");
//     overlay.className = "modal-overlay";

//     const modal = document.createElement("div");
//     modal.className = "modal-card error";

//     modal.innerHTML = `
//         <div class="modal-icon error-icon">
//             <svg viewBox="0 0 24 24" fill="none">
//                 <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
//                 <path d="M15 9l-6 6M9 9l6 6"
//                       stroke="currentColor"
//                       stroke-width="2"
//                       stroke-linecap="round"/>
//             </svg>
//         </div>

//         <h2>Error</h2>
//         <p>${message}</p>

//         <button class="modal-btn error-btn">Close</button>
//     `;

//     overlay.appendChild(modal);
//     document.body.appendChild(overlay);

//     requestAnimationFrame(() => overlay.classList.add("show"));

//     const close = () => {
//         overlay.classList.remove("show");
//         setTimeout(() => overlay.remove(), 250);
//     };

//     modal.querySelector(".error-btn").onclick = close;

//     overlay.onclick = (e) => {
//         if (e.target === overlay) close();
//     };

//     document.addEventListener("keydown", function esc(e) {
//         if (e.key === "Escape") {
//             close();
//             document.removeEventListener("keydown", esc);
//         }
//     });
// }

// // Spinner CSS
// const style = document.createElement("style");
// style.innerHTML = `
// .spinner {
//     border: 3px solid rgba(255,255,255,0.3);
//     border-top: 3px solid #fff;
//     border-radius: 50%;
//     width: 18px;
//     height: 18px;
//     display: inline-block;
//     margin-right: 8px;
//     animation: spin 0.8s linear infinite;
// }
// @keyframes spin {
//     0% { transform: rotate(0deg); }
//     100% { transform: rotate(360deg); }
// }
// `;
// document.head.appendChild(style);

// // ---------- Grab Elements ----------
// const showInvoiceBtn = document.getElementById("show-invoice-btn");
// const viewInvoicesBtn = document.querySelector(".btn.secondary");

// // ---------- Button Events ----------
// if (showInvoiceBtn) {
//     showInvoiceBtn.addEventListener("click", (e) => {
//         e.preventDefault();
//         setLoading(showInvoiceBtn, "Opening Invoice...");
//         // Redirect after small delay for spinner effect
//         setTimeout(() => {
//             clearLoading(showInvoiceBtn);
//             window.location.href = "/create/invoice";
//         }, 500);
//     });
// }

// if (viewInvoicesBtn) {
//     viewInvoicesBtn.addEventListener("click", (e) => {
//         e.preventDefault();
//         setLoading(viewInvoicesBtn, "Loading Invoices...");
//         setTimeout(() => {
//             clearLoading(viewInvoicesBtn);
//             window.location.href = "/invoices";
//         }, 500);
//     });
// }

// // ---------- Optional: Dynamic greeting ----------
// // dashboard.js

// document.addEventListener("DOMContentLoaded", () => {
//     const greetingText = document.getElementById("greeting-text");
//     const usernamePlaceholder = document.getElementById("username-placeholder");

//     if (greetingText && usernamePlaceholder) {
//         const now = new Date();
//         const hour = now.getHours();
//         let timeGreeting = "Welcome back";

//         if (hour < 12) timeGreeting = "Good morning";
//         else if (hour < 18) timeGreeting = "Good afternoon";
//         else timeGreeting = "Good evening";

//         // Use the username injected by Flask
//         const username = usernamePlaceholder.textContent || "";
//         greetingText.innerHTML = `${timeGreeting}, ${username} 👋`;
//     }
// });




// // document.addEventListener('DOMContentLoaded', function() {
// //       const header = document.querySelector('header');
// //       const navUl = header.querySelector('aside');
// //       // Create toggle button
// //       const btn = document.createElement('button');
// //       btn.className = 'nav-toggle';
// //       btn.setAttribute('aria-label', 'Toggle navigation');
// //       btn.innerHTML = '&#9776;';
// //       nav.insertBefore(btn, navUl);
// //       btn.addEventListener('click', function() {
// //         navUl.classList.toggle('open');
// //       });
// //       // Close menu on link click (mobile)
// //       navUl.querySelectorAll('a').forEach(link => {
// //         link.addEventListener('click', function() {
// //           if(window.innerWidth <= 700) navUl.classList.remove('open');
// //         });
// //       });
// //     });

// // const toggle = document.getElementById('menuToggle');
// // const sidebar = document.getElementById('sidebar');
// // const overlay = document.getElementById('sidebarOverlay');

// // toggle.addEventListener('click', () => {
// //     sidebar.classList.add('open');
// //     overlay.classList.add('active');
// //     document.body.style.overflow = 'hidden';
// // });

// // overlay.addEventListener('click', closeSidebar);

// // function closeSidebar() {
// //     sidebar.classList.remove('open');
// //     overlay.classList.remove('active');
// //     document.body.style.overflow = '';
// // }

// // // Close on resize to desktop
// // window.addEventListener('resize', () => {
// //     if (window.innerWidth >= 1024) {
// //         closeSidebar();
// //     }
// // });


// // document.querySelectorAll('.fa-eye').forEach(eye => {
// //     eye.addEventListener('click', (e) => {
// //         e.preventDefault();
// //         eye.classList.toggle('fa-eye-slash');
// //     });
// // });




// const Gotoprofile = document.getElementById("dashboard-profile-pic");
// Gotoprofile.addEventListener('click', (e) => {
//     e.preventDefault();
//     window.location.href = "/profile";
// });

// const helpBtn = document.getElementById("helpBtn");
// helpBtn.addEventListener('click', (e) => {
//     e.preventDefault();
//     window.location.href = "/support";
// });

// const notifyBtn = document.getElementById("notifyBtn");
// notifyBtn.addEventListener('click', (e) => {
//     e.preventDefault();
//     window.location.href = "/notifications";
// });



// const notifyCount = document.getElementById("notifyCount")
// const unreadCount = parseInt(notifyCount.dataset.count);
// console.log("Unread Count:", unreadCount);

// if (unreadCount > 0) {
//     notifyCount.style.display = "flex";
//     notifyCount.textContent = unreadCount;
// } else {
//     notifyCount.style.display = "none";
// }

// const count = parseInt(notifyCount.dataset.count) || 0;
//     if (count > 0) {
//                 notifyCount.textContent = count > 9 ? '9+' : count;
//                 notifyCount.style.display = 'block';
//             }

// document.getElementById("notifyBtn").addEventListener("click", () => {
//     fetch("/notifications/mark-read", { method: "POST" })
//         .then(() => {
//             notifyCount.style.display = "none";
//         });
// });

//   document.addEventListener('DOMContentLoaded', () => {
//             // DOM Elements
//             const notifyBtn = document.getElementById('notifyBtn');
//             const helpBtn = document.getElementById('helpBtn');
//             const eyeIcon = document.getElementById('eye');
//             const greetingText = document.getElementById('greeting-text');
//             const notifyCount = document.getElementById('notifyCount');
//             const showInvoiceBtn = document.getElementById('show-invoice-btn');
//             const particlesContainer = document.getElementById('particles');
//             const refreshIndicator = document.getElementById('refreshIndicator');
//             const scrollIndicator = document.getElementById('scrollIndicator');
//             const content = document.querySelector('.content');
            
           
            
//             // Toggle balance visibility
//             let balanceVisible = true;
//             eyeIcon.addEventListener('click', () => {
//                 eyeIcon.classList.add('haptic-feedback');
//                 setTimeout(() => {
//                     eyeIcon.classList.remove('haptic-feedback');
//                 }, 200);
                
//                 balanceVisible = !balanceVisible;
//                 const eyeSvg = eyeIcon.querySelector('svg');
                
//                 if (balanceVisible) {
//                     eyeSvg.innerHTML = `
//                         <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" fill="none" stroke="currentColor" stroke-width="2"/>
//                         <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="2"/>
//                     `;
//                     document.querySelector('.balance-amount a').innerHTML = '$12,450.00 <svg viewBox="0 0 24 24"><path d="M5 12h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="m12 5 7 7-7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
//                 } else {
//                     eyeSvg.innerHTML = `
//                         <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
//                         <line x1="1" y1="1" x2="23" y2="23" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
//                     `;
//                     document.querySelector('.balance-amount a').innerHTML = '•••••••• <svg viewBox="0 0 24 24"><path d="M5 12h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="m12 5 7 7-7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
//                 }
//             });
            
//             // Notification button click
//             notifyBtn.addEventListener('click', () => {
//                 notifyBtn.classList.add('haptic-feedback');
//                 setTimeout(() => {
//                     notifyBtn.classList.remove('haptic-feedback');
//                 }, 200);
                
//                 // Hide notification badge
//                 notifyCount.style.display = 'none';
                
//                 // Show notification animation
//                 notifyBtn.style.transform = 'scale(0.95)';
//                 setTimeout(() => {
//                     notifyBtn.style.transform = '';
//                     // In a real app, this would open notifications
//                     showToast('🔔 Notification center opened');
//                 }, 200);
//             });
            
//             // Help button click
//             helpBtn.addEventListener('click', () => {
//                 helpBtn.classList.add('haptic-feedback');
//                 setTimeout(() => {
//                     helpBtn.classList.remove('haptic-feedback');
//                 }, 200);
                
//                 helpBtn.style.transform = 'scale(0.95)';
//                 setTimeout(() => {
//                     helpBtn.style.transform = '';
//                     showToast('🎧 Help center opened');
//                 }, 200);
//             });
            
//             // Create invoice button click
//             showInvoiceBtn.addEventListener('click', (e) => {
//                 e.preventDefault();
//                 showInvoiceBtn.classList.add('haptic-feedback');
//                 setTimeout(() => {
//                     showInvoiceBtn.classList.remove('haptic-feedback');
//                 }, 200);
                
//                 showInvoiceBtn.disabled = true;
//                 showInvoiceBtn.innerHTML = `
//                     <svg viewBox="0 0 24 24" style="animation: spin 1s linear infinite;">
//                         <path d="M12 2v6m0 10v6M4.93 4.93l4.24 4.24m8.49-8.49l4.24 4.24M1.5 12h6m10 0h6M4.93 19.07l4.24-4.24m8.49 8.49l4.24-4.24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
//                     </svg>
//                     Creating...
//                 `;
                
//                 setTimeout(() => {
//                     showInvoiceBtn.disabled = false;
//                     showInvoiceBtn.innerHTML = `
//                         <svg viewBox="0 0 24 24">
//                             <line x1="12" y1="5" x2="12" y2="19" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
//                             <line x1="5" y1="12" x2="19" y2="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
//                         </svg>
//                         Create Invoice
//                     `;
//                     showToast('✨ New invoice created successfully!');
//                 }, 1500);
//             });
            
//             // Pull to refresh simulation
//             let startY = 0;
//             let currentY = 0;
//             let isRefreshing = false;
            
//             content.addEventListener('touchstart', (e) => {
//                 if (window.scrollY === 0 && !isRefreshing) {
//                     startY = e.touches[0].clientY;
//                 }
//             }, { passive: true });
            
//             content.addEventListener('touchmove', (e) => {
//                 if (window.scrollY === 0 && !isRefreshing && startY > 0) {
//                     currentY = e.touches[0].clientY;
//                     const pullDistance = currentY - startY;
                    
//                     if (pullDistance > 0 && pullDistance < 150) {
//                         refreshIndicator.style.transform = `translateX(-50%) scale(${pullDistance / 100})`;
//                     }
                    
//                     if (pullDistance > 80) {
//                         refreshIndicator.classList.add('active');
//                     } else {
//                         refreshIndicator.classList.remove('active');
//                     }
//                 }
//             }, { passive: true });
            
//             content.addEventListener('touchend', () => {
//                 if (refreshIndicator.classList.contains('active') && !isRefreshing) {
//                     isRefreshing = true;
//                     refreshIndicator.style.transform = 'translateX(-50%) scale(1.2)';
                    
//                     setTimeout(() => {
//                         refreshIndicator.style.transform = 'translateX(-50%) scale(0)';
//                         refreshIndicator.classList.remove('active');
//                         showToast('✓ Data refreshed successfully');
                        
//                         // Simulate data refresh
//                         setTimeout(() => {
//                             isRefreshing = false;
//                         }, 1000);
//                     }, 800);
//                 } else {
//                     refreshIndicator.style.transform = 'translateX(-50%) scale(0)';
//                     refreshIndicator.classList.remove('active');
//                 }
                
//                 startY = 0;
//                 currentY = 0;
//             }, { passive: true });
            
//             // Scroll indicator
//             window.addEventListener('scroll', () => {
//                 if (window.scrollY > 300) {
//                     scrollIndicator.classList.add('visible');
//                 } else {
//                     scrollIndicator.classList.remove('visible');
//                 }
//             });
            
//             scrollIndicator.addEventListener('click', () => {
//                 window.scrollTo({
//                     top: 0,
//                     behavior: 'smooth'
//                 });
//                 scrollIndicator.classList.remove('visible');
//             });
            
//             // Create floating particles
//             function createParticles() {
//                 const particleCount = window.innerWidth > 768 ? 30 : 15;
                
//                 for (let i = 0; i < particleCount; i++) {
//                     const particle = document.createElement('div');
//                     particle.classList.add('particle');
                    
//                     // Random size between 3px and 10px
//                     const size = Math.random() * 7 + 3;
//                     particle.style.width = `${size}px`;
//                     particle.style.height = `${size}px`;
                    
//                     // Random position
//                     particle.style.left = `${Math.random() * 100}%`;
//                     particle.style.top = `${Math.random() * 100}%`;
                    
//                     // Random animation duration and delay
//                     const duration = Math.random() * 10 + 15;
//                     const delay = Math.random() * 5;
//                     particle.style.animationDuration = `${duration}s`;
//                     particle.style.animationDelay = `${delay}s`;
                    
//                     // Random opacity
//                     particle.style.opacity = `${Math.random() * 0.5 + 0.1}`;
                    
//                     particlesContainer.appendChild(particle);
//                 }
//             }
            
//             // Show toast notification
//             function showToast(message) {
//                 if (document.getElementById('toast')) {
//                     document.getElementById('toast').remove();
//                 }
                
//                 const toast = document.createElement('div');
//                 toast.id = 'toast';
//                 toast.style.cssText = `
//                     position: fixed;
//                     bottom: calc(90px + var(--safe-area-bottom));
//                     left: 50%;
//                     transform: translateX(-50%) translateY(100px);
//                     background: rgba(255, 255, 255, 0.95);
//                     color: var(--dark);
//                     padding: 14px 24px;
//                     border-radius: 50px;
//                     box-shadow: var(--shadow-lg);
//                     z-index: 1000;
//                     font-weight: 500;
//                     transition: transform 0.3s ease, opacity 0.3s ease;
//                     max-width: 85%;
//                     text-align: center;
//                     backdrop-filter: blur(12px);
//                     border: 1px solid rgba(0,0,0,0.08);
//                 `;
//                 toast.textContent = message;
//                 document.body.appendChild(toast);
                
//                 // Animate in
//                 setTimeout(() => {
//                     toast.style.transform = 'translateX(-50%) translateY(0)';
//                 }, 10);
                
//                 // Animate out and remove
//                 setTimeout(() => {
//                     toast.style.transform = 'translateX(-50%) translateY(100px)';
//                     toast.style.opacity = '0';
//                     setTimeout(() => {
//                         toast.remove();
//                     }, 300);
//                 }, 2500);
//             }
            
//             // Initialize
//             createParticles();
            
//             // Simulate notification count
//             const count = parseInt(notifyCount.dataset.count) || 0;
//             if (count > 0) {
//                 notifyCount.textContent = count > 9 ? '9+' : count;
//                 notifyCount.style.display = 'block';
//             }
            
//             // Add CSS animations
//             const style = document.createElement('style');
//             style.innerHTML = `
//                 @keyframes spin {
//                     0% { transform: rotate(0deg); }
//                     100% { transform: rotate(360deg); }
//                 }
//                 @keyframes haptic {
//                     0% { transform: translateX(0); }
//                     25% { transform: translateX(-2px); }
//                     50% { transform: translateX(2px); }
//                     75% { transform: translateX(-2px); }
//                     100% { transform: translateX(0); }
//                 }
//                 .haptic-feedback {
//                     animation: haptic 0.15s ease-in-out;
//                 }
//             `;
//             document.head.appendChild(style);
            
//             // Simulate app-like feel with initial animations
//             setTimeout(() => {
//                 document.querySelectorAll('.stat-card').forEach((card, index) => {
//                     card.style.animation = `fadeInDown 0.5s ease-out ${0.3 + index * 0.1}s both`;
//                 });
                
//                 document.querySelectorAll('.activity-item').forEach((item, index) => {
//                     item.style.animation = `fadeInDown 0.5s ease-out ${0.5 + index * 0.1}s both`;
//                 });
//             }, 300);
//         });



// ===============================
// dashboard.js – FULL & FINAL
// ===============================

/* ---------- GLOBAL HELPERS ---------- */
function setLoading(button, text = "Processing...") {
    if (!button) return;
    button.disabled = true;
    button.dataset.text = button.innerHTML;
    button.innerHTML = `<span class="spinner"></span> ${text}`;
}

function clearLoading(button) {
    if (!button) return;
    button.disabled = false;
    button.innerHTML = button.dataset.text;
}

/* ---------- MODALS ---------- */
function showModal(type, message, redirect = null) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    overlay.innerHTML = `
        <div class="modal-card ${type}">
            <div class="modal-icon">
                ${type === "error"
                    ? `<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6l-12 12" stroke="currentColor" stroke-width="2"/></svg>`
                    : `<svg viewBox="0 0 24 24"><path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2"/></svg>`
                }
            </div>
            <h2>${type === "error" ? "Error" : "Success"}</h2>
            <p>${message}</p>
            <button class="modal-btn">Continue</button>
        </div>
    `;

    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add("show"));

    overlay.querySelector(".modal-btn").onclick = () => {
        overlay.remove();
        if (redirect) window.location.href = redirect;
    };

    overlay.onclick = e => {
        if (e.target === overlay) overlay.remove();
    };
}

/* ---------- TOAST ---------- */
function showToast(message) {
    document.getElementById("toast")?.remove();

    const toast = document.createElement("div");
    toast.id = "toast";
    toast.className = "toast";
    toast.textContent = message;

    document.body.appendChild(toast);
    setTimeout(() => toast.classList.add("show"), 10);
    setTimeout(() => toast.remove(), 2800);
}

/* ---------- STYLES ---------- */
const style = document.createElement("style");
style.innerHTML = `
.spinner {
    border:3px solid rgba(255,255,255,.3);
    border-top:3px solid #fff;
    border-radius:50%;
    width:18px;height:18px;
    animation:spin .8s linear infinite;
    display:inline-block;
}
@keyframes spin{to{transform:rotate(360deg)}}

.modal-overlay{
    position:fixed;inset:0;
    background:rgba(0,0,0,.55);
    display:flex;
    align-items:center;
    justify-content:center;
    opacity:0;
    transition:.25s;
    z-index:9999;
}
.modal-overlay.show{opacity:1}
.modal-card{
    background:#fff;
    padding:28px;
    border-radius:14px;
    text-align:center;
    max-width:420px;width:100%;
}
.toast{
    position:fixed;
    bottom:40px;
    left:50%;
    transform:translateX(-50%) translateY(120px);
    background:#111827;
    color:#fff;
    padding:12px 22px;
    border-radius:50px;
    transition:.3s;
    z-index:9999;
}
.toast.show{transform:translateX(-50%) translateY(0)}
.haptic-feedback{animation:haptic .15s}
@keyframes haptic{
    25%{transform:translateX(-2px)}
    50%{transform:translateX(2px)}
    75%{transform:translateX(-2px)}
}
.particle{
    position:absolute;
    background:rgba(255,255,255,.15);
    border-radius:50%;
    animation:float linear infinite;
}
@keyframes float{to{transform:translateY(-120vh)}}
`;
document.head.appendChild(style);

/* ---------- DOM READY ---------- */
document.addEventListener("DOMContentLoaded", () => {

    // Core elements
    const showInvoiceBtn = document.getElementById("show-invoice-btn");
    const viewInvoicesBtn = document.querySelector(".btn.secondary");
    const notifyBtn = document.getElementById("notifyBtn");
    const notifyCount = document.getElementById("notifyCount");
    const helpBtn = document.getElementById("helpBtn");
    const profilePic = document.getElementById("dashboard-profile-pic");
    const greetingText = document.getElementById("greeting-text");
    const usernamePlaceholder = document.getElementById("username-placeholder");
    const eyeIcon = document.getElementById("eye");
    const particlesContainer = document.getElementById("particles");
    const refreshIndicator = document.getElementById("refreshIndicator");
    const scrollIndicator = document.getElementById("scrollIndicator");
    const content = document.querySelector(".content");

    /* ---------- GREETING ---------- */
    if (greetingText && usernamePlaceholder) {
        const hour = new Date().getHours();
        const greet =
            hour < 12 ? "Good morning" :
            hour < 18 ? "Good afternoon" :
            "Good evening";
        greetingText.innerHTML = `${greet}, ${usernamePlaceholder.textContent} 👋`;
    }

    /* ---------- BUTTON NAV ---------- */
    showInvoiceBtn?.addEventListener("click", e => {
        e.preventDefault();
        setLoading(showInvoiceBtn, "Opening...");
        setTimeout(() => window.location.href = "/create/invoice", 500);
    });

    viewInvoicesBtn?.addEventListener("click", e => {
        e.preventDefault();
        setLoading(viewInvoicesBtn, "Loading...");
        setTimeout(() => window.location.href = "/invoices", 500);
    });

    profilePic?.addEventListener("click", () => {
        window.location.href = "/profile";
    });

    helpBtn?.addEventListener("click", () => {
        window.location.href = "/support";
    });

    /* ---------- NOTIFICATIONS ---------- */
    const count = parseInt(notifyCount?.dataset.count || 0);
    if (notifyCount && count > 0) {
        notifyCount.textContent = count > 9 ? "9+" : count;
        notifyCount.style.display = "flex";
    }

    notifyBtn?.addEventListener("click", () => {
        notifyCount.style.display = "none";
        fetch("/notifications/mark-read", { method: "POST" });
        showToast("🔔 Notifications opened");
        window.location.href = "/notifications";
    });

    /* ---------- BALANCE TOGGLE ---------- */
    let balanceVisible = true;
    eyeIcon?.addEventListener("click", () => {
        balanceVisible = !balanceVisible;
        eyeIcon.classList.add("haptic-feedback");
        setTimeout(() => eyeIcon.classList.remove("haptic-feedback"), 200);

        document.querySelector(".balance-amount a").textContent =
            balanceVisible ? "$12,450.00" : "••••••••";
    });

    /* ---------- PARTICLES ---------- */
    function createParticles() {
        if (!particlesContainer) return;
        const count = window.innerWidth > 768 ? 30 : 15;
        for (let i = 0; i < count; i++) {
            const p = document.createElement("div");
            p.className = "particle";
            const size = Math.random() * 7 + 3;
            p.style.width = p.style.height = `${size}px`;
            p.style.left = `${Math.random() * 100}%`;
            p.style.top = `${Math.random() * 100}%`;
            p.style.animationDuration = `${Math.random() * 10 + 15}s`;
            p.style.opacity = Math.random() * .5 + .1;
            particlesContainer.appendChild(p);
        }
    }

    /* ---------- PULL TO REFRESH ---------- */
    let startY = 0;
    content?.addEventListener("touchstart", e => {
        if (window.scrollY === 0) startY = e.touches[0].clientY;
    }, { passive: true });

    content?.addEventListener("touchend", () => {
        if (startY > 0) {
            showToast("✓ Data refreshed");
            startY = 0;
        }
    }, { passive: true });

    /* ---------- SCROLL TO TOP ---------- */
    window.addEventListener("scroll", () => {
        scrollIndicator?.classList.toggle("visible", window.scrollY > 300);
    });

    scrollIndicator?.addEventListener("click", () => {
        window.scrollTo({ top: 0, behavior: "smooth" });
    });

    /* ---------- INIT ---------- */
    createParticles();
});

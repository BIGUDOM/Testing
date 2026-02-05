// Skip intro forever if already seen
if (localStorage.getItem("intro_seen")) {
    window.location.href = "/login";
}
document.addEventListener('DOMContentLoaded', () => {
            // DOM Elements
            const cards = document.querySelectorAll('.intro-card');
            const dots = document.querySelectorAll('.dot');
            const nextBtn = document.getElementById('nextBtn');
            const particlesContainer = document.getElementById('particles');
            
            // State
            let currentSlide = 0;
            const totalSlides = cards.length;
            
            // Initialize particles
            createParticles();
            
            // Event Listeners
            nextBtn.addEventListener('click', goToNextSlide);
            
            dots.forEach(dot => {
                dot.addEventListener('click', () => {
                    const index = parseInt(dot.getAttribute('data-index'));
                    goToSlide(index);
                });
            });
            
            // Functions
            function goToNextSlide() {
                if (currentSlide < totalSlides - 1) {
                    goToSlide(currentSlide + 1);
                } else {
                    // Last slide - could redirect to main app
                    localStorage.setItem("intro_seen", "true");
                     window.location.href = "/register";

                }
            }
            
            function goToSlide(index) {
                // Update button text on last slide
                if (index === totalSlides - 1) {
                    nextBtn.textContent = 'Get Started';
                } else {
                    nextBtn.textContent = 'Continue';
                }
                
                // Update active card
                cards.forEach((card, i) => {
                    card.classList.remove('active', 'prev');
                    if (i === index) {
                        card.classList.add('active');
                    } else if (i < index) {
                        card.classList.add('prev');
                    }
                });
                
                // Update dots
                dots.forEach((dot, i) => {
                    dot.classList.toggle('active', i === index);
                });
                
                // Update background gradient
                const gradients = [
                    'var(--gradient-1)',
                    'var(--gradient-2)',
                    'var(--gradient-3)'
                ];
                
                document.querySelector('.intro-wrapper').style.background = gradients[index];
                
                // Update current slide
                currentSlide = index;
            }
            
            function createParticles() {
                const particleCount = 15;
                
                for (let i = 0; i < particleCount; i++) {
                    const particle = document.createElement('div');
                    particle.classList.add('particle');
                    
                    // Random size between 3px and 10px
                    const size = Math.random() * 7 + 3;
                    particle.style.width = `${size}px`;
                    particle.style.height = `${size}px`;
                    
                    // Random position
                    particle.style.left = `${Math.random() * 100}%`;
                    particle.style.top = `${Math.random() * 100}%`;
                    
                    // Random animation duration and delay
                    const duration = Math.random() * 10 + 10;
                    const delay = Math.random() * 5;
                    particle.style.animationDuration = `${duration}s`;
                    particle.style.animationDelay = `${delay}s`;
                    
                    // Random opacity
                    particle.style.opacity = `${Math.random() * 0.5 + 0.1}`;
                    
                    particlesContainer.appendChild(particle);
                }
            }
            
            // Auto-advance for demo purposes (comment out in production)
     
            setInterval(() => {
                if (currentSlide < totalSlides - 1) {
                    goToSlide(currentSlide + 1);
                } else {
                    goToSlide(0);
                }
            }, 5000);
          
        });

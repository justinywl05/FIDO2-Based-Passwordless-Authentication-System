/* Portal Common UI Logic */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Initialize Theme from localStorage or system preference
    const savedTheme = localStorage.getItem("portal-theme") || "dark";
    document.documentElement.setAttribute("data-theme", savedTheme);
    updateThemeToggleIcon(savedTheme);

    // 2. Initialize Accent Color
    const savedAccent = localStorage.getItem("portal-accent") || "violet";
    document.documentElement.setAttribute("data-accent", savedAccent);

    // 3. Initialize Sidebar Collapse state
    const sidebar = document.querySelector(".sidebar");
    const sidebarOverlay = document.getElementById("sidebar-overlay");
    const isMobileLayout = () => window.matchMedia("(max-width: 900px)").matches;
    const savedSidebarCollapsed = localStorage.getItem("portal-sidebar-collapsed") === "true";
    if (sidebar && savedSidebarCollapsed && !isMobileLayout()) {
        sidebar.classList.add("collapsed");
    }

    const closeMobileSidebar = () => {
        if (!sidebar) return;
        sidebar.classList.remove("mobile-open");
        sidebarOverlay?.classList.remove("active");
        document.body.classList.remove("mobile-nav-open");
    };

    const syncSidebarForViewport = () => {
        if (!sidebar) return;

        if (isMobileLayout()) {
            sidebar.classList.remove("collapsed");
            closeMobileSidebar();
        } else {
            sidebar.classList.toggle("collapsed", localStorage.getItem("portal-sidebar-collapsed") === "true");
            closeMobileSidebar();
        }
    };

    // Bind theme toggles
    const themeToggleBtn = document.getElementById("theme-toggle-btn");
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", toggleTheme);
    }

    // Bind sidebar collapse toggle
    const sidebarToggleBtn = document.getElementById("sidebar-toggle-btn");
    if (sidebarToggleBtn) {
        sidebarToggleBtn.addEventListener("click", () => {
            if (sidebar) {
                if (isMobileLayout()) {
                    const isOpen = sidebar.classList.toggle("mobile-open");
                    sidebarOverlay?.classList.toggle("active", isOpen);
                    document.body.classList.toggle("mobile-nav-open", isOpen);
                } else {
                    sidebar.classList.toggle("collapsed");
                    localStorage.setItem("portal-sidebar-collapsed", sidebar.classList.contains("collapsed"));
                }
            }
        });
    }

    sidebarOverlay?.addEventListener("click", closeMobileSidebar);
    document.querySelectorAll(".sidebar-menu-item a").forEach(link => {
        link.addEventListener("click", () => {
            if (isMobileLayout()) closeMobileSidebar();
        });
    });
    window.addEventListener("resize", syncSidebarForViewport);

    // 4. Highlight current sidebar menu item based on window location
    highlightCurrentMenuItem();
});

// Toast notification helper
function showToast(message, type = "info") {
    // Find or create toast container
    let container = document.querySelector(".toast-container");
    if (!container) {
        container = document.createElement("div");
        container.className = "toast-container";
        document.body.appendChild(container);
    }

    // Create toast
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    // Choose icon
    let iconClass = "fa-info-circle";
    if (type === "success") iconClass = "fa-check-circle";
    else if (type === "warning") iconClass = "fa-exclamation-triangle";
    else if (type === "error") iconClass = "fa-times-circle";

    toast.innerHTML = `<i class="fas ${iconClass}"></i> <span>${message}</span>`;
    
    container.appendChild(toast);

    // Auto remove
    setTimeout(() => {
        toast.style.animation = "slideInUp 0.3s ease reverse";
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 4000);
}

// Toggle light/dark theme
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("portal-theme", newTheme);
    updateThemeToggleIcon(newTheme);
    
    showToast(`Switched to ${newTheme} mode`, "info");
}

function updateThemeToggleIcon(theme) {
    const icon = document.querySelector("#theme-toggle-btn i");
    if (icon) {
        if (theme === "dark") {
            icon.className = "fas fa-sun";
        } else {
            icon.className = "fas fa-moon";
        }
    }
}

// Accent customization
function setAccentColor(accentName) {
    document.documentElement.setAttribute("data-accent", accentName);
    localStorage.setItem("portal-accent", accentName);
    
    // Update active class on color picker elements if present
    document.querySelectorAll(".color-option").forEach(opt => {
        opt.classList.remove("active");
        if (opt.getAttribute("data-color") === accentName) {
            opt.classList.add("active");
        }
    });

    showToast(`Theme accent changed to ${accentName}`, "success");
}

// Sidebar highlighters
function highlightCurrentMenuItem() {
    const path = window.location.pathname;
    document.querySelectorAll(".sidebar-menu-item").forEach(item => {
        item.classList.remove("active");
        const link = item.querySelector("a");
        if (link) {
            const href = link.getAttribute("href");
            if (href && (path === href || path.startsWith(href + "?") || (href !== "/" && path.includes(href)))) {
                item.classList.add("active");
            }
        }
    });
}

// Modal actions
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add("active");
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove("active");
    }
}

// Quick Demo Login helper
function demoLogin(email, password) {
    const emailField = document.getElementById("Email");
    const passField = document.getElementById("Password");
    
    if (emailField && passField) {
        emailField.value = email;
        passField.value = password;
        
        showToast("Demo credentials filled! Logging in...", "success");
        setTimeout(() => {
            document.querySelector("form").submit();
        }, 800);
    }
}

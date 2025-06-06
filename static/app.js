// Animated dark theme index.js

// Animated fade-in for sections, nav scroll, and contact form UX
document.addEventListener("DOMContentLoaded", () => {
  // Fade-in animation for sections
  const sections = document.querySelectorAll(".section");
  const revealSections = () => {
    const trigger = window.innerHeight * 0.85;
    sections.forEach((section) => {
      const rect = section.getBoundingClientRect();
      if (rect.top < trigger) {
        section.classList.add("visible");
      }
    });
  };
  window.addEventListener("scroll", revealSections);
  revealSections();

  // Smooth scroll for nav links
  document.querySelectorAll("nav a").forEach((link) => {
    link.addEventListener("click", (e) => {
      const href = link.getAttribute("href");
      if (href.startsWith("#")) {
        e.preventDefault();
        document.querySelector(href).scrollIntoView({ behavior: "smooth" });
      }
    });
  });
});

function scrollToSection(id) {
  document.getElementById(id).scrollIntoView({ behavior: "smooth" });
}

// Contact form UX (demo only)
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("contactForm");
  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const status = document.getElementById("formStatus");
      status.textContent = "Sending...";
      setTimeout(() => {
        status.textContent = "Thank you for your message! (Demo only)";
        form.reset();
      }, 1200);
    });
  }
});

// Simple JS for form submission (demo only)
document.addEventListener("DOMContentLoaded", function () {
  const form = document.querySelector("form");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      alert("Thank you, " + form.name.value + "! Your message was received.");
      form.reset();
    });
  }
});

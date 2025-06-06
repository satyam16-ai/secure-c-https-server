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

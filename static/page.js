(() => {
  "use strict";
  const themeToggle = document.querySelector("#theme-toggle");
  const themeIcon = document.querySelector("#theme-icon");

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("phishlens.theme", theme);
    } catch {
      // Keep the selected theme for this page even if browser storage is disabled.
    }
    themeIcon.textContent = theme === "light" ? "☾" : "☼";
  }

  themeToggle.addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
  });
  try {
    if (localStorage.getItem("phishlens.theme") === "light") setTheme("light");
  } catch {
    // Use the default dark theme when browser storage is unavailable.
  }
})();

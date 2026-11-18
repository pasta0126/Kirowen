"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const ui = SwaggerUIBundle({
    url: "/openapi.yaml",
    dom_id: "#swagger",
    deepLinking: true,
    tryItOutEnabled: true,
    persistAuthorization: false, // do not leave the token in localStorage
    displayRequestDuration: true,
    defaultModelsExpandDepth: 0,
    onComplete: () => {
      // Token handed over by the registration page, for this tab only.
      let token = null;
      try { token = sessionStorage.getItem("kirowen.token"); } catch (_) { /* storage blocked */ }
      if (token) ui.preauthorizeApiKey("token", token);
    },
  });
});

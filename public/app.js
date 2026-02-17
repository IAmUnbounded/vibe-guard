"use strict";

const copyBtn = document.getElementById("copy-btn");
const commandEl = document.getElementById("command");

if (copyBtn && commandEl) {
  copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(commandEl.textContent || "");
      copyBtn.textContent = "Copied";
      setTimeout(() => {
        copyBtn.textContent = "Copy command";
      }, 1400);
    } catch (_error) {
      copyBtn.textContent = "Copy failed";
      setTimeout(() => {
        copyBtn.textContent = "Copy command";
      }, 1400);
    }
  });
}

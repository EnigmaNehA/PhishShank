document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("checkForm");
  const input = document.getElementById("urlInput");
  const resultBox = document.getElementById("result");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = input.value.trim();

    // Reset state
    resultBox.className = "result loading";
    resultBox.textContent = "🔍 Checking URL...";

    try {
      const response = await fetch("/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      resultBox.className = "result";

      if (data.result === "High Risk") {
        resultBox.classList.add("high-risk");
        resultBox.innerHTML = `<span class="icon">❌</span> <strong>High Risk:</strong> Detected by model and Google.`;
      } else if (data.result === "Suspicious") {
        resultBox.classList.add("suspicious");
        resultBox.innerHTML = `<span class="icon">⚠️</span> <strong>Suspicious:</strong> Detected by model or Google.`;
      } else if (data.result === "Safe") {
        resultBox.classList.add("safe");
        resultBox.innerHTML = `<span class="icon">✅</span> <strong>Safe:</strong> No threat detected.`;
      } else {
        resultBox.classList.add("error");
        resultBox.textContent = "❌ Unknown response from server.";
      }
    } catch (err) {
      resultBox.className = "result error";
      resultBox.textContent = "❌ Error checking URL. Please try again.";
    }
  });
});

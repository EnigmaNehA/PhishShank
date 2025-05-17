const apiUrl = "/predict";

async function checkURL() {
  const urlInput = document.getElementById("urlInput");
  const resultDiv = document.getElementById("result");
  const url = urlInput.value.trim();

  resultDiv.className = "";
  if (!url) {
    resultDiv.textContent = "Please enter a URL.";
    resultDiv.classList.add("show");
    return;
  }

  try {
    new URL(url);
  } catch {
    resultDiv.textContent = "Invalid URL format.";
    resultDiv.classList.add("show");
    return;
  }

  resultDiv.textContent = "Checking...";
  resultDiv.classList.add("show");

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error(`Status ${response.status}`);

    const data = await response.json();

    // Example backend returns {"prediction": "Phishing"} or {"prediction": "Legitimate"}
    if (data.prediction === "Phishing") {
      resultDiv.className = "show phishing";
      resultDiv.textContent = "⚠️ This URL is likely a phishing website!";
    } else if (data.prediction === "Legitimate") {
      resultDiv.className = "show safe";
      resultDiv.textContent = "✅ This URL appears safe.";
    } else {
      resultDiv.className = "show";
      resultDiv.textContent = "Unexpected response from server.";
    }
  } catch (err) {
    console.error("Fetch error:", err);
    resultDiv.className = "show";
    resultDiv.textContent = "Error checking URL. Please try again later.";
  }
}

document.getElementById("submitBtn").addEventListener("click", e => {
  e.preventDefault(); // prevent form submission
  checkURL();
});

document.getElementById("urlInput").addEventListener("keypress", e => {
  if (e.key === "Enter") {
    e.preventDefault();
    checkURL();
  }
});

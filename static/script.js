const apiUrl = "/predict";

const submitBtn = document.getElementById("submitBtn");

async function checkURL() {
  const urlInput = document.getElementById("urlInput");
  const resultDiv = document.getElementById("result");
  const url = urlInput.value.trim();

  // Clear previous classes
  resultDiv.className = "";

  if (!url) {
    resultDiv.textContent = "Please enter a URL.";
    resultDiv.classList.add("show", "error");
    return;
  }

  try {
    new URL(url);
  } catch {
    resultDiv.textContent = "Invalid URL format.";
    resultDiv.classList.add("show", "error");
    return;
  }

  resultDiv.textContent = "Checking...";
  resultDiv.classList.add("show");

  submitBtn.disabled = true; // disable button during check

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) throw new Error(`Status ${response.status}`);

    const data = await response.json();

    if (data.prediction === "Phishing") {
      resultDiv.className = "show phished";
      resultDiv.textContent = "⚠️ This URL is likely a phishing website!";
    } else if (data.prediction === "Legitimate") {
      resultDiv.className = "show safe";
      resultDiv.textContent = "✅ This URL appears safe.";
    } else {
      resultDiv.className = "show error";
      resultDiv.textContent = "Unexpected response from server.";
    }
  } catch (err) {
    console.error("Fetch error:", err);
    resultDiv.className = "show error";
    resultDiv.textContent = "Error checking URL. Please try again later.";
  } finally {
    submitBtn.disabled = false; // re-enable button
  }
}

submitBtn.addEventListener("click", (e) => {
  e.preventDefault(); // prevent form submission
  checkURL();
});

document.getElementById("urlInput").addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    checkURL();
  }
});

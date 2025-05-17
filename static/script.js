// script.js (Enhanced & Integrated Version)

const apiUrl = "/check_url";

function isValidURL(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

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

  if (!isValidURL(url)) {
    resultDiv.textContent = "Invalid URL format.";
    resultDiv.classList.add("show");
    return;
  }

  resultDiv.textContent = "Checking...";
  resultDiv.classList.add("show");

  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`Error: ${response.status}`);
    }

    const data = await response.json();

    // Adjust according to backend response structure
    if (data.prediction === 1) {
      resultDiv.className = "show phishing";
      resultDiv.textContent = "⚠️ This URL is likely a phishing website!";
    } else if (data.prediction === 0) {
      resultDiv.className = "show safe";
      resultDiv.textContent = "✅ This URL appears safe.";
    } else {
      resultDiv.className = "show";
      resultDiv.textContent = "Unexpected response. Please try again later.";
    }
  } catch (error) {
    console.error("Fetch error:", error);
    resultDiv.className = "show";
    resultDiv.textContent = "Error checking URL. Please try again later.";
  }
}

document.getElementById("checkBtn").addEventListener("click", checkURL);
document.getElementById("urlInput").addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    checkURL();
  }
});

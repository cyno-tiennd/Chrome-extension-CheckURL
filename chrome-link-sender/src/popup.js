// popup.js

document.addEventListener('DOMContentLoaded', () => {
  const urlInput = document.getElementById('urlInput');
  const checkButton = document.getElementById('checkButton');
  const loadingDiv = document.getElementById('loading');
  const vtStatus = document.getElementById('vt-status');
  const errorMessage = document.getElementById('errorMessage');
  const googleStatus = document.getElementById('gsb-status');
  const localStatus = document.getElementById('local-status'); // Thêm element để hiển thị trạng thái local

  // Hàm để cập nhật trạng thái hiển thị
  function updateStatus(element, text, className) {
    element.textContent = text;
    element.className = className; // Đặt class CSS để đổi màu
  }

  // Hàm đặt lại trạng thái ban đầu
  function resetStatus() {
    updateStatus(localStatus, "Still haven't checked", "unknown"); // Reset trạng thái local
    updateStatus(vtStatus, "Still haven't checked", "unknown");
    updateStatus(googleStatus, "Still haven't checked", "unknown");
    errorMessage.textContent = "";
    loadingDiv.style.display = 'none'; // Ẩn trạng thái loading
  }

  // Đặt lại trạng thái khi popup được mở lần đầu
  resetStatus();

  checkButton.addEventListener('click', async () => {
    const urlToCheck = urlInput.value.trim();

    if (!urlToCheck) {
      errorMessage.textContent = "Please input URL.";
      return;
    }

    resetStatus();
    loadingDiv.style.display = 'block'; 
    errorMessage.textContent = "";

    try {
      // Gửi tin nhắn đến background script
      const response = await chrome.runtime.sendMessage({ 
        type: "scanUrl", 
        url: urlToCheck 
      });
      
      loadingDiv.style.display = 'none'; // Ẩn loading khi có kết quả

      if (response) {
        // HIỂN THỊ KẾT QUẢ TỪ BACKGROUND
        // Kiểm tra kết quả kiểm tra cục bộ trước
        if (response.isPoisonedLocally) {
          updateStatus(localStatus, response.localMessage, "unsafe");
          // Nếu có trong list poison cục bộ, không hiển thị kết quả từ server nữa
          // và có thể ẩn các trường server nếu bạn muốn
          updateStatus(vtStatus, "Skipped (local check)", "unknown");
          updateStatus(googleStatus, "Skipped (local check)", "unknown");
          errorMessage.textContent = ""; // Đảm bảo không có lỗi tổng quát
        } else {
          // Nếu không có trong list poison cục bộ, hiển thị kết quả backend
          updateStatus(localStatus, "Not found in local list", "safe");
          updateResultsFromBackend(response); // Hàm mới để cập nhật kết quả từ backend
        }
      } else {
        errorMessage.textContent = "Can't get response from background, please check again.";
      }

    } catch (error) {
      loadingDiv.style.display = 'none';
      errorMessage.textContent = `An error happened when sending request: ${error.message}`;
      console.error("Error sending message to background:", error);
    }
  });

  // Hàm cập nhật kết quả từ backend vào các trường hiển thị
  function updateResultsFromBackend(response) {
    const results = response.backendResult;
    const error = response.backendError;

    if (error) {
      errorMessage.textContent = `Backend processing error: ${error}`;
      updateStatus(vtStatus, "Backend Error", "error-msg");
      updateStatus(googleStatus, "Backend Error", "error-msg");
      return;
    }

    if (!results) {
      errorMessage.textContent = "No valid results received from backend.";
      updateStatus(vtStatus, "No Data", "unknown");
      updateStatus(googleStatus, "No Data", "unknown");
      return;
    }

    // VirusTotal
    if (results.virusTotal && results.virusTotal.data) {
      const vtData = results.virusTotal.data;
      const attributes = vtData.attributes;
      
      if (attributes && attributes.status === 'completed') {
        const stats = attributes.stats;

        if (stats) {
          const malicious = stats.malicious || 0;
          const suspicious = stats.suspicious || 0;
          const undetected = stats.undetected || 0;
          const harmless = stats.harmless || 0;

          if (malicious > 0 || suspicious > 0) {
            updateStatus(vtStatus, `Dangerous: ${malicious} độc hại, ${suspicious} đáng ngờ`, "unsafe");
          } else if (harmless > 0 || undetected > 0) {
            updateStatus(vtStatus, "Safety", "safe");
          } else {
            updateStatus(vtStatus, "Data is not clear", "unknown");
          }
        } else {
          updateStatus(vtStatus, "No detailed stats from VirusTotal", "unknown");
        }
      } else if (attributes && (attributes.status === 'queued' || attributes.status === 'pending')) {
        updateStatus(vtStatus, "Analysing...", "pending");
      } else {
        updateStatus(vtStatus, "Unknown status from VirusTotal", "unknown");
      }
    } else if (results.virusTotal && results.virusTotal.error) {
      updateStatus(vtStatus, `Error: ${results.virusTotal.error}`, "error-msg");
    } else {
      updateStatus(vtStatus, "No data from VirusTotal", "unknown");
    }

    // Google Safe Browse
    if(results.googleSafeBrowse) {
      if (results.googleSafeBrowse.isSafe) {
        updateStatus(googleStatus, `Safety`, "safe");
      } else {
        updateStatus(googleStatus, "Unsafety", "unsafe"); 
      }
    } else if (results.googleSafeBrowse && results.googleSafeBrowse.error) {
      updateStatus(googleStatus, `Error: ${results.googleSafeBrowse.error}`, "error-msg");
    } else {
      updateStatus(googleStatus, "No data from Google Safe Browse", "unknown");
    }
  }
});
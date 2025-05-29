// background.js

let localPoisonUrls = [];

/**
 * Tải danh sách URL độc hại từ file poisonURL.txt.
 * File này phải nằm trong thư mục gốc của tiện ích mở rộng.
 */
async function loadPoisonUrls() {
    try {
        const url = chrome.runtime.getURL('poisonURL.txt');
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`Failed to load poisonURL.txt: ${response.status} - ${response.statusText}`);
        }

        const text = await response.text();
        localPoisonUrls = text.split('\n')
                               .map(s => s.trim())
                               .filter(s => s.length > 0);

        console.log("Loaded local poison URLs:", localPoisonUrls);
    } catch (error) {
        console.error("Error loading poisonURL.txt:", error);
        localPoisonUrls = [];
    }
}

// Gọi hàm tải danh sách URL khi Service Worker (background script) khởi động
loadPoisonUrls();

// --- Lắng nghe tin nhắn từ Popup ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "scanUrl") {
    const urlToScan = request.url;

    // Khởi tạo một đối tượng kết quả sẽ được gửi về popup.js
    let responseData = {
        url: urlToScan,
        isPoisonedLocally: false, // Mặc định không bị nhiễm độc cục bộ
        localMessage: "",
        backendResult: null, // Kết quả từ backend
        backendError: null   // Lỗi từ backend
    };

    // BƯỚC 1: Kiểm tra URL trong danh sách độc hại cục bộ
    if (localPoisonUrls.includes(urlToScan)) {
        console.warn(`URL ${urlToScan} found in local poison list.`);
        responseData.isPoisonedLocally = true;
        responseData.localMessage = "URL is identified as potentially malicious by local list.";
    }

    // BƯỚC 2: Gọi API backend SONG SONG
    // (Bất kể có nằm trong list poison cục bộ hay không, vẫn gọi backend để lấy thông tin chi tiết)
    fetch('http://localhost:8005/api/check-url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: urlToScan })
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(errorData => {
                throw new Error(`Backend HTTP Error (${response.status}): ${errorData.error || JSON.stringify(errorData)}`);
            }).catch(() => {
                throw new Error(`Backend HTTP Error (${response.status}): ${response.statusText}`);
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('Backend raw response:', data);
        responseData.backendResult = data; // Lưu kết quả từ backend
    })
    .catch(error => {
        console.error('Error calling backend API:', error);
        responseData.backendError = error.message; // Lưu lỗi từ backend
    })
    .finally(() => {
        // Gửi kết quả cuối cùng về popup.js sau khi cả hai quá trình (nếu có) hoàn tất
        sendResponse(responseData);
    });

    // Quan trọng: return true để cho Chrome biết rằng bạn sẽ gửi phản hồi
    // một cách bất đồng bộ (sau khi fetch hoàn thành)
    return true;
  }
});
// background.js

// 1. Nên dùng Set thay vì Array cho localPoisonUrls để tra cứu nhanh hơn (O(1) thay vì O(n))
let localPoisonUrls = new Set();

/**
 * Tải danh sách URL độc hại từ file poisonURL.txt.
 * File này phải nằm trong thư mục gốc của tiện ích mở rộng.
 * Đảm bảo đã thêm "poisonURL.txt" vào "web_accessible_resources" trong manifest.json để tiện ích mở rộng có thể đọc được.
 */
async function loadPoisonUrls() {
    try {
        const url = chrome.runtime.getURL('poisonURL.txt');
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error(`Tải poisonURL.txt thất bại: ${response.status} - ${response.statusText}`);
        }

        const text = await response.text();
        const urls = text.split('\n')
                               .map(s => s.trim())
                               .filter(s => s.length > 0);
        
        localPoisonUrls = new Set(urls); // Cập nhật Set với dữ liệu mới
        console.log("Đã tải các URL độc hại cục bộ:", localPoisonUrls.size, "URL(s)");
    } catch (error) {
        console.error("Lỗi khi tải poisonURL.txt:", error);
        localPoisonUrls = new Set(); // Đảm bảo Set rỗng nếu có lỗi
    }
}

// Gọi hàm tải danh sách URL khi Service Worker (background script) khởi động
loadPoisonUrls();

// --- Lắng nghe tin nhắn từ Popup ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "scanUrl") {
    // 2. Sửa lỗi `url` không định nghĩa: sử dụng `request.url`
    let urlToScan = request.url; 
    // Chuẩn hóa URL: thêm http:// hoặc https:// nếu thiếu, để khớp với định dạng trong poisonURL.txt
    if (!urlToScan.startsWith('http://') && !urlToScan.startsWith('https://')) {
      urlToScan = `https://${urlToScan}`; // Giả định mặc định là https, bạn có thể cân nhắc http
    }
    
    // Khởi tạo một đối tượng kết quả sẽ được gửi về popup.js
    let responseData = {
        url: request.url, // Giữ URL gốc từ request để hiển thị trên popup
        isPoisonedLocally: false, // Mặc định không bị nhiễm độc cục bộ
        localMessage: "",
        backendResult: null, // Kết quả từ backend
        backendError: null   // Lỗi từ backend
    };

    // BƯỚC 1: Kiểm tra URL trong danh sách độc hại cục bộ
    // 3. Sử dụng .has() cho Set để kiểm tra
    if (localPoisonUrls.has(urlToScan)) { 
        console.warn(`[Background] URL "${urlToScan}" được tìm thấy trong danh sách độc hại cục bộ. Phản hồi ngay lập tức đến popup.`);
        responseData.isPoisonedLocally = true;
        responseData.localMessage = "URL được xác định là có khả năng độc hại bởi danh sách cục bộ.";

        // 4. Giả lập kết quả nguy hiểm từ VT/GSB để popup có thể hiển thị thống nhất
        // Điều này giúp popup.js không cần biết nguồn kết quả là từ đâu
        responseData.virusTotal = {
            data: {
                attributes: {
                    status: 'completed',
                    stats: { malicious: 1, suspicious: 0, harmless: 0, undetected: 0 } // Giả lập là độc hại
                }
            },
            message: 'Được tìm thấy trong danh sách độc hại cục bộ'
        };
        responseData.googleSafeBrowse = {
            isSafe: false, // Giả lập là không an toàn
            message: "Được tìm thấy trong danh sách độc hại cục bộ"
        };
        
        // 5. Gửi phản hồi ngay lập tức cho popup.js
        sendResponse(responseData);

        // 6. Gửi yêu cầu đến backend NHƯNG KHÔNG CHỜ PHẢN HỒI (fire-and-forget)
        // Dù đã phản hồi cho popup, bạn vẫn có thể gửi request đến backend để backend ghi log
        // hoặc thực hiện các kiểm tra chuyên sâu khác mà không làm chậm UI.
        fetch('http://localhost:8005/api/check-url', { // <-- Đảm bảo đây là URL backend của bạn
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: request.url }) // Gửi URL gốc về backend
        })
        .then(backendResponse => {
            if (!backendResponse.ok) {
                console.error("[Background] Backend phản hồi lỗi sau kiểm tra cục bộ:", backendResponse.status);
            } else {
                console.log("[Background] Backend đã xử lý URL sau kiểm tra cục bộ.");
            }
        })
        .catch(error => {
            console.error("[Background] Lỗi gửi URL đến backend sau kiểm tra cục bộ:", error);
        });

        // 7. Quan trọng: return true để cho Chrome biết rằng bạn sẽ gửi phản hồi
        // (đã gửi phản hồi ở dòng sendResponse(responseData) ở trên)
        return true; 
    }

    // BƯỚC 2: Nếu không có trong danh sách cục bộ, gửi yêu cầu đến backend và đợi phản hồi như cũ
    console.log(`[Background] URL "${urlToScan}" không có trong danh sách độc hại cục bộ. Gửi đến backend để kiểm tra đầy đủ.`);
    fetch('http://localhost:8005/api/check-url', { // <-- Đảm bảo đây là URL backend của bạn
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: request.url }) // Gửi URL gốc về backend
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(errorData => {
                throw new Error(`Lỗi HTTP Backend (${response.status}): ${errorData.error || JSON.stringify(errorData)}`);
            }).catch(() => {
                throw new Error(`Lỗi HTTP Backend (${response.status}): ${response.statusText}`);
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('[Background] Phản hồi thô từ Backend:', data);
        responseData.backendResult = data; // Lưu kết quả từ backend
        sendResponse(responseData); // Gửi kết quả cuối cùng về popup.js
    })
    .catch(error => {
        console.error('[Background] Lỗi gọi API backend:', error);
        responseData.backendError = error.message; // Lưu lỗi từ backend
        sendResponse(responseData); // Gửi phản hồi lỗi về popup.js
    });

    // 8. Quan trọng: return true để cho Chrome biết rằng bạn sẽ gửi phản hồi bất đồng bộ
    return true; 
  }
});
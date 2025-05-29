// controllers/safeBrowseController.js
const axios = require('axios');
const { GOOGLE_SAFE_Browse_API_KEY, VIRUSTOTAL_API_KEY } = require('../config/constants');

const GOOGLE_SAFE_Browse_API_URL = 'https://safeBrowse.googleapis.com/v4/threatMatches:find';
const VIRUSTOTAL_SUBMIT_URL_API = `https://www.virustotal.com/api/v3/urls`;
const VIRUSTOTAL_ANALYSIS_API_BASE = `https://www.virustotal.com/api/v3/analyses`;


/**
 * Gửi URL đến VirusTotal để quét và sau đó truy vấn kết quả.
 * @param {string} url - URL cần quét.
 * @returns {Promise<Object>} Kết quả phân tích từ VirusTotal hoặc đối tượng lỗi.
 */
async function checkUrlWithVirusTotal(url) {
  const submitOptions = {
    method: 'POST',
    headers: {
      'x-apikey': VIRUSTOTAL_API_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    },
    data: `url=${encodeURIComponent(url)}` // Gửi URL cần quét trong body
  };

  try {
    // Bước 1: Gửi URL để quét và lấy Analysis ID
    const submitResponse = await axios(VIRUSTOTAL_SUBMIT_URL_API, submitOptions);
    const submitData = submitResponse.data;

    console.log("VirusTotal Submit Result:", submitData);

    // Kiểm tra xem submitData có chứa data.id không
    if (!submitData || !submitData.data || !submitData.data.id) {
        throw new Error("VirusTotal did not return a valid analysis ID.");
    }

    const analysisId = submitData.data.id;

    // Bước 2: Truy vấn kết quả phân tích bằng Analysis ID
    // Backend có thể đợi lâu hơn Service Worker mà không bị tắt.
    // Thực tế có thể cần polling với giới hạn số lần thử.
    await new Promise(resolve => setTimeout(resolve, 3000)); // Đợi 3 giây để phân tích có thể bắt đầu

    const analysisResult = await getVirusTotalAnalysisResult(analysisId);
    return analysisResult; // Trả về kết quả phân tích đầy đủ
  } catch (error) {
    console.error("Error checking with VirusTotal:", error.response ? error.response.data : error.message);
    throw new Error(`VirusTotal Check Error: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
  }
}

async function getVirusTotalAnalysisResult(analysisId) {
    const apiUrl = `${VIRUSTOTAL_ANALYSIS_API_BASE}/${analysisId}`;
    const options = {
        method: 'GET',
        headers: {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'Accept': 'application/json'
        }
    };

    try {
        const response = await axios(apiUrl, options);
        return response.data; // Trả về kết quả phân tích
    } catch (error) {
        console.error("Error getting VirusTotal analysis result:", error.response ? error.response.data : error.message);
        throw new Error(`VirusTotal Analysis Result Error: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
    }
}


async function checkUrlSafetyWithGoogle(urlToCheck) {
  const apiUrl = `${GOOGLE_SAFE_Browse_API_URL}?key=${GOOGLE_SAFE_Browse_API_KEY}`;

  const requestBody = {
    client: {
      clientId: "chrome-link-sender-backend", // Thay đổi theo tên ứng dụng của bạn
      clientVersion: "1.0.0"     // Thay đổi theo phiên bản ứng dụng của bạn
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [
        { "url": urlToCheck }
      ]
    }
  };

  try {
    const response = await axios.post(apiUrl, requestBody);
    const data = response.data;

    if (Object.keys(data).length === 0) {
      // Nếu data là đối tượng rỗng, URL an toàn
      return { url: urlToCheck, isSafe: true, message: "URL is safe (Google Safe Browse)" };
    } else {
      // Nếu có dữ liệu, URL không an toàn
      return { url: urlToCheck, isSafe: false, matches: data.matches, message: "URL is not safe (Google Safe Browse)" };
    }

  } catch (error) {
    console.error("Error when checking URL with Google Safe Browse:", error.response ? error.response.data : error.message);
    throw new Error(`Google Safe Browse Error: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
  }
}


// Main controller function to handle incoming requests
exports.checkUrlAndIntegrate = async (req, res) => {
    const { url } = req.body; // Expecting { "url": "http://example.com" } from extension

    if (!url) {
        return res.status(400).json({ error: 'URL is required.' });
    }

    try {
        // Use Promise.allSettled to wait for all promises to complete,
        // no matter if they succeed or fail, collects results in an array.
        const [virusTotalResult, googleSafeBrowseResult] = await Promise.allSettled([
            checkUrlWithVirusTotal(url),
            checkUrlSafetyWithGoogle(url)
        ]);

        const responseData = {
            url: url,
            virusTotal: virusTotalResult.status === 'fulfilled'
                ? virusTotalResult.value
                : { error: virusTotalResult.reason.message || "Failed VirusTotal scan" },
            googleSafeBrowse: googleSafeBrowseResult.status === 'fulfilled'
                ? googleSafeBrowseResult.value
                : { error: googleSafeBrowseResult.reason.message || "Failed Google Safe Browse scan" }
        };

        // Gửi kết quả tổng hợp về cho client (extension)
        res.status(200).json(responseData);

    } catch (error) {
        console.error('Unexpected error in backend:', error);
        res.status(500).json({
            error: 'Failed to process URL safety check on backend.',
            details: error.message
        });
    }
};
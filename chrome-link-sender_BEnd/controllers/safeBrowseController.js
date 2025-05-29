// controllers/safeBrowseController.js
const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');

const { GOOGLE_SAFE_Browse_API_KEY, VIRUSTOTAL_API_KEY } = require('../config/constants');

const GOOGLE_SAFE_Browse_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const VIRUSTOTAL_SUBMIT_URL_API = `https://www.virustotal.com/api/v3/urls`;
const VIRUSTOTAL_ANALYSIS_API_BASE = `https://www.virustotal.com/api/v3/analyses`;

// Định nghĩa đường dẫn tới file log
const LOG_FILE_PATH = path.join(__dirname, '..', 'log', 'data_url.txt'); // File sẽ nằm trong thư mục log/ ở thư mục gốc của backend

// Cấu hình cho Short Polling của VirusTotal
const VT_POLL_INTERVAL_MS = 4000; // Khoảng thời gian chờ giữa các lần polling (3 giây)
const VT_MAX_POLL_ATTEMPTS = 3; // Số lần polling tối đa (3 giây * 20 lần = 60 giây tối đa chờ)


/**
 * Ghi kết quả quét vào một file văn bản.
 * @param {string} url - URL đã quét.
 * @param {object} virusTotalResult - Kết quả từ VirusTotal.
 * @param {object} googleSafeBrowseResult - Kết quả từ Google Safe Browse.
 */
async function logScanResultToFile(url, virusTotalResult, googleSafeBrowseResult) {
    let vtStatus = "Unknown";
    
    if (virusTotalResult.data && virusTotalResult.data.attributes && virusTotalResult.data.attributes.status === 'completed') {
      const stats = virusTotalResult.data.attributes.stats;
      if (stats) {
          const malicious = stats.malicious || 0;
          const suspicious = stats.suspicious || 0;
          if (malicious > 0 || suspicious > 0) {
              vtStatus = "Unsafe";
          } else {
              vtStatus = "Safe";
          }
      }
    }


    let gsbStatus = "Unknown";
    if (googleSafeBrowseResult.isSafe !== undefined) {
      gsbStatus = googleSafeBrowseResult.isSafe ? "Safe" : "Unsafe";
    }

    const logEntry = `URL: "${url}"\nVirusTotal: ${vtStatus}\nGoogle Safe Browse: ${gsbStatus}\n---\n`;

    try {
        await fs.appendFile(LOG_FILE_PATH, logEntry, 'utf8');
        console.log(`[Log] Scan result for "${url}" saved to ${LOG_FILE_PATH}`);
    } catch (err) {
        console.error(`[Log Error] Failed to write scan result to file: ${err.message}`);
    }
}


/**
 * Hàm lấy kết quả phân tích VirusTotal bằng Analysis ID.
 * Đây là hàm nội bộ được sử dụng bởi pollVirusTotalAnalysisResult.
 */
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
        console.log(`[VirusTotal] Getting analysis result for ID: ${analysisId}`);
        const response = await axios(apiUrl, options);
        return response.data; // Trả về kết quả phân tích đầy đủ
    } catch (error) {
        console.error("[VirusTotal] Error getting VirusTotal analysis result:", error.response ? JSON.stringify(error.response.data, null, 2) : error.message);
        // Throw error so pollVirusTotalAnalysisResult can catch and handle it
        throw new Error(`VirusTotal Analysis Result Error: ${error.response && error.response.data ? JSON.stringify(error.response.data) : error.message}`);
    }
}


/**
 * Thực hiện short polling để lấy kết quả phân tích VirusTotal.
 * @param {string} analysisId - ID phân tích từ VirusTotal.
 * @returns {Promise<Object>} Kết quả phân tích cuối cùng khi hoàn thành.
 */
async function pollVirusTotalAnalysisResult(analysisId) {
    for (let i = 0; i < VT_MAX_POLL_ATTEMPTS; i++) {
        try {
            const result = await getVirusTotalAnalysisResult(analysisId);
            const status = result.data && result.data.attributes ? result.data.attributes.status : null;

            // console.log(`[VirusTotal Polling] Attempt ${i + 1}/${VT_MAX_POLL_ATTEMPTS} - Status: ${status}`);

            if (status === 'completed') {
                return result; // Phân tích hoàn tất, trả về kết quả
            } else if (status === 'queued' || status === 'pending') {
                // Tiếp tục polling
                await new Promise(resolve => setTimeout(resolve, VT_POLL_INTERVAL_MS));
            } else {
                // Các trạng thái khác (ví dụ: 'failed' hoặc không xác định)
                return {
                    // Dữ liệu giả định để logScanResultToFile có thể phân tích
                    data: { attributes: { status: 'failed_or_unexpected_status' } },
                    message: `VirusTotal analysis returned unexpected status: "${status || 'unknown'}".`
                };
            }
        } catch (error) {
            return {
                // Dữ liệu giả định để logScanResultToFile có thể phân tích
                data: { attributes: { status: 'api_polling_error' } },
                message: `VirusTotal polling encountered an API error: ${error.message}.`
            };
        }
    }
    return getVirusTotalAnalysisResult(analysisId); // Trả về kết quả cuối cùng nếu timeout, có hàm xử lý dữ liệu chưa phân tích xong ở frontend
}


/**
 * Gửi URL đến VirusTotal để quét và sau đó polling kết quả.
 * @param {string} url - URL cần quét.
 * @returns {Promise<Object>} Kết quả phân tích cuối cùng từ VirusTotal hoặc đối tượng lỗi.
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
    console.log(`[VirusTotal] Submitting URL for analysis: ${url}`);
    const submitResponse = await axios(VIRUSTOTAL_SUBMIT_URL_API, submitOptions);
    const submitData = submitResponse.data;

    //console.log("[VirusTotal] Submit Result:", JSON.stringify(submitData, null, 2));

    if (!submitData || !submitData.data || !submitData.data.id) {
        throw new Error("VirusTotal did not return a valid analysis ID.");
    }

    const analysisId = submitData.data.id;

    // Bước 2: Bắt đầu polling để lấy kết quả phân tích
    
    const finalAnalysisResult = await pollVirusTotalAnalysisResult(analysisId);
    //console.log("[VirusTotal] Final Analysis Result (from polling):", JSON.stringify(finalAnalysisResult, null, 2));
    return finalAnalysisResult; // Trả về kết quả phân tích đầy đủ
  } catch (error) {
    console.error("[VirusTotal] Error in checkUrlWithVirusTotal:", error.response ? JSON.stringify(error.response.data, null, 2) : error.message);
    throw new Error(`VirusTotal Check Error: ${error.message}`);
  }
}


async function checkUrlSafetyWithGoogle(urlToCheck) {
  if (!urlToCheck.startsWith('http://') && !urlToCheck.startsWith('https://')) {
    urlToCheck = `http://${urlToCheck}`;
  }

  const apiUrl = `${GOOGLE_SAFE_Browse_API_URL}?key=${GOOGLE_SAFE_Browse_API_KEY}`;

  const requestBody = {
    client: {
      clientId: "chrome-link-sender-backend",
      clientVersion: "1.0.0"
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
    console.log(`[Google Safe Browse] Checking URL: ${urlToCheck}`);
    //console.log("[Google Safe Browse] Request Body:", JSON.stringify(requestBody, null, 2));
    
    const response = await axios.post(apiUrl, requestBody, {
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    });
    const data = response.data;

    console.log("[Google Safe Browse] Raw API Response:", JSON.stringify(data, null, 2));

    if (Object.keys(data).length === 0) {
      return { url: urlToCheck, isSafe: true, message: "URL is safe (Google Safe Browse)" };
    } else if (data.matches && data.matches.length > 0) {
      return { url: urlToCheck, isSafe: false, matches: data.matches, message: "URL is not safe (Google Safe Browse)" };
    } else {
      console.warn("[Google Safe Browse] Unexpected non-empty response without matches:", data);
      return { url: urlToCheck, isSafe: null, message: "Google Safe Browse: Unexpected API response structure." };
    }

  } catch (error) {
    console.error("[Google Safe Browse] Error when checking URL:", error.message);
    if (error.response) {
      console.error("[Google Safe Browse] Error Response Status:", error.response.status);
      console.error("[Google Safe Browse] Error Response Data:", JSON.stringify(error.response.data, null, 2));
      
      if (error.response.status === 400) {
        throw new Error(`Google Safe Browse API Error: Bad Request. Check your URL format or API key. Details: ${JSON.stringify(error.response.data)}`);
      } else if (error.response.status === 403) {
        throw new Error(`Google Safe Browse API Error: Forbidden. Check your API Key permissions or quota. Details: ${JSON.stringify(error.response.data)}`);
      } else if (error.response.status === 500) {
        throw new Error(`Google Safe Browse API Error: Internal Server Error. Details: ${JSON.stringify(error.response.data)}`);
      } else {
        throw new Error(`Google Safe Browse HTTP Error (${error.response.status}): ${error.response.statusText}. Details: ${JSON.stringify(error.response.data)}`);
      }
    } else if (error.request) {
      throw new Error(`Google Safe Browse Network Error: No response received. ${error.message}`);
    } else {
      throw new Error(`Google Safe Browse Request Setup Error: ${error.message}`);
    }
  }
}


// Main controller function to handle incoming requests
exports.checkUrlAndIntegrate = async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required.' });
    }

    try {
        console.log(`[Backend] Received request for URL: ${url}`);
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

        // Ghi log kết quả vào file
        await logScanResultToFile(
            url,
            responseData.virusTotal,
            responseData.googleSafeBrowse
        );

        res.status(200).json(responseData);

    } catch (error) {
        console.error('[Backend] Unexpected error in backend:', error);
        res.status(500).json({
            error: 'Failed to process URL safety check on backend.',
            details: error.message
        });
    }
};
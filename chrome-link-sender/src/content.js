(async () => {
  const currentUrl = window.location.href;
  const serverUrl = 'http://localhost:8005/'; // Thay bằng URL server FastAPI của bạn

  try {
    const response = await fetch(serverUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: currentUrl }) // Gửi dữ liệu theo cấu trúc Pydantic model
    });

    if (response.ok) {
      const data = await response.json();
      console.log('Server response:', data.message, 'Received URL:', data.received_url);
    } else {
      console.error('Failed to send URL:', response.status);
    }
  } catch (error) {
    console.error('Error sending URL:', error);
  }
})();
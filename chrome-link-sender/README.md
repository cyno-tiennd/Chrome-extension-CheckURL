# Chrome Link Sender

Chrome Link Sender is a simple Chrome extension that captures the current page's URL and sends it to a specified server. This extension is useful for tracking or logging URLs visited by users.

## Features

- Captures the current tab's URL.
- Sends the URL to a server for processing.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/chrome-link-sender.git
   ```

2. Navigate to the project directory:
   ```
   cd chrome-link-sender
   ```

3. Load the extension in Chrome:
   - Open Chrome and go to `chrome://extensions/`.
   - Enable "Developer mode" in the top right corner.
   - Click on "Load unpacked" and select the `chrome-link-sender` directory.

## Usage

Once the extension is loaded, it will automatically capture the URL of the current tab whenever you navigate to a new page. The URL will be sent to the server specified in the `src/utils.js` file.

## Configuration

To configure the server URL, modify the `sendUrlToServer` function in `src/utils.js`.

## Contributing

Feel free to submit issues or pull requests if you have suggestions or improvements for the project.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

# Chrome Link Sender

A Chrome extension that sends the current page URL to a server.

## Features

- Sends the current tab's URL to your server with one click.
- Clean, modern popup UI.

## Setup

1. Add your icon images to the `images/` folder.
2. Update the server URL in `src/background.js` if needed.
3. Load the extension in Chrome via `chrome://extensions` > "Load unpacked".

## Folder Structure

- `manifest.json` — Extension manifest.
- `popup.html`, `popup.css`, `src/popup.js` — Popup UI and logic.
- `src/background.js` — Background script.
- `src/content.js` — Content script (currently empty).
- `images/` — Place your icon images here.
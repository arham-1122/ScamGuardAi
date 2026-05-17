# ScamGuard

ScamGuard is a production-ready Chrome Extension (Manifest V3) that provides real-time, AI-powered protection against phishing, fake stores, crypto scams, and manipulative social engineering patterns. 

It works by extracting structural and contextual signals from the active web page and analyzing them securely using Anthropic's Claude 3.5 Sonnet API.

## 🚀 Features

- 🔍 Real-time URL scam analysis
- 🛡️ Phishing detection system
- ⚡ Fast browser-side scanning
- 📌 Popup dashboard with quick status checks
- 🧠 AI-inspired heuristic analysis
- 🚫 Malicious site warning alerts
- ⚙️ Custom settings/options page
- 📊 Clean and lightweight UI

## Architecture Overview

ScamGuard uses a layered analysis approach to minimize latency and prevent unnecessary API calls:
1. **Content Script Extraction**: On load, `content-script.js` extracts domain info, form fields, iframe stats, manipulation keywords, and up to 6000 characters of text.
2. **Static Heuristics Engine**: Before AI is invoked, `lib/rules.js` computes a baseline score. If the site is mathematically completely safe, or blatantly malicious, it can bypass the AI entirely.
3. **Caching Layer**: Results are hashed and cached via IndexedDB (`lib/cache.js`) for 24 hours to prevent redundant API calls on page reloads.
4. **Rate Limiting**: To prevent API spam, a Token Bucket algorithm (`lib/rate-limiter.js`) limits requests to 20 per minute with a burst of 5.
5. **Claude API**: The filtered signals are sent securely to Anthropic's API using Prompt Caching for near-instant contextual risk assessment.

## Installation (Developer Mode)

1. Clone or download this repository.
2. Open Google Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** using the toggle switch in the top right corner.
4. Click the **Load unpacked** button.
5. Select the `scamguard` folder.

## Configuration & API Key

ScamGuard requires an Anthropic API Key to utilize Claude for semantic analysis.

1. Get an API key from the [Anthropic Console](https://console.anthropic.com/).
2. Click the ScamGuard extension icon in your browser toolbar to open the Popup.
3. Click the gear icon (**⚙️**) in the bottom right corner to open Options.
4. Paste your API key into the input field and click **Save Key**. 
   *(Note: The key is stored securely in your browser's local sync storage).*
5. You can also configure your sensitivity tier and whitelist from this page.

## Sensitivity Tiers
* **Conservative**: Only flags sites structurally identified as highly dangerous (Score ≥ 75).
* **Balanced** *(Default)*: Flags medium-risk manipulation and dark patterns (Score ≥ 45).
* **Aggressive**: Flags minor trust issues or aggressive marketing (Score ≥ 25).

## Known Limitations
* **Single Page Applications (SPAs)**: The extension uses a `MutationObserver` to re-trigger analysis if the DOM changes heavily on navigation, but fast dynamic transitions might bypass deep scanning.
* **Cost**: Frequent navigation without caching will consume Anthropic API credits.
* **DeclarativeNetRequest**: Auto-blocking is currently architected but requires declarative rule hydration via `chrome.declarativeNetRequest.updateDynamicRules` which must be implemented for full active blocking.

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request!

## Screenshot
<img width="399" height="205" alt="image" src="https://github.com/user-attachments/assets/3c7dfc42-b5a0-496d-80af-74a5346e6fbc" />


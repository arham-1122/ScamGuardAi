import { Analyzer } from '../lib/analyzer.js';

let pendingAnalyses = new Map();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SCAN_PENDING" && sender.tab) {
        const tabId = sender.tab.id;
        chrome.storage.session.remove([`verdict_${tabId}`]);
        chrome.action.setBadgeText({ text: '...', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#888888', tabId });
        return;
    }

    if (message.type === "ANALYZE_PAGE" && sender.tab) {
        const tabId = sender.tab.id;

        // Check whitelist first
        chrome.storage.sync.get(['whitelist', 'sensitivity', 'autoBlock', 'notificationsEnabled'], async (prefs) => {
            const whitelist = Array.isArray(prefs.whitelist) ? prefs.whitelist : [];
            if (whitelist.some(w => message.payload.domain.includes(w))) {
                // Whitelisted domain
                chrome.action.setBadgeText({ text: '✓', tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#1E8E3E', tabId });
                return;
            }

            try {
                const verdict = await Analyzer.analyze(message.payload);

                // Save to session for Popup retrieval
                await chrome.storage.session.set({ [`verdict_${tabId}`]: verdict });

                // Update badge based on user prefs sensitivity
                let scoreThreshold = 45; // balanced
                if (prefs.sensitivity === 'aggressive') scoreThreshold = 25;
                if (prefs.sensitivity === 'conservative') scoreThreshold = 75;

                if (verdict.risk_score >= 75) {
                    chrome.action.setBadgeText({ text: '⚠', tabId });
                    chrome.action.setBadgeBackgroundColor({ color: '#D93025', tabId });

                    if (prefs.notificationsEnabled !== false) {
                        chrome.notifications.create({
                            type: 'basic',
                            iconUrl: '../icons/icon-128.png',
                            title: 'ScamGuard Alert',
                            message: verdict.user_warning || "High risk site detected!"
                        });
                    }

                    if (prefs.autoBlock && verdict.risk_score >= 90) {
                        // Future feature: add dynamic rules
                        // chrome.declarativeNetRequest.updateDynamicRules(...)
                    }

                } else if (verdict.risk_score >= scoreThreshold) {
                    chrome.action.setBadgeText({ text: '?', tabId });
                    chrome.action.setBadgeBackgroundColor({ color: '#F29900', tabId });
                } else {
                    chrome.action.setBadgeText({ text: '✓', tabId });
                    chrome.action.setBadgeBackgroundColor({ color: '#1E8E3E', tabId });
                }

                // Broadcast to content script
                chrome.tabs.sendMessage(tabId, { type: "VERDICT", payload: verdict }).catch(e => {
                    // ignore if content script missing
                });

            } catch (error) {
                console.error('Analysis error for tab', tabId, error);
            }
        });
    }
});

chrome.webNavigation.onCommitted.addListener((details) => {
    // wake up extension context
    if (details.frameId === 0) {
        chrome.storage.session.remove([`verdict_${details.tabId}`]);
        chrome.action.setBadgeText({ text: '...', tabId: details.tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#888888', tabId: details.tabId });
    }
});

// Periodic alarms if needed
chrome.alarms.onAlarm.addListener((alarm) => {
    // Unused at the moment but keeps background active
});

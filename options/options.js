document.addEventListener('DOMContentLoaded', () => {
    // Load existing config
    chrome.storage.sync.get(['apiKey', 'sensitivity', 'autoBlock', 'notificationsEnabled', 'whitelist'], (data) => {
        if (data.apiKey) document.getElementById('api-key').value = data.apiKey;
        if (data.sensitivity) document.getElementById('sensitivity').value = data.sensitivity;
        if (data.autoBlock !== undefined) document.getElementById('auto-block').checked = data.autoBlock;
        if (data.notificationsEnabled !== undefined) document.getElementById('notifications').checked = data.notificationsEnabled;
        if (data.whitelist) document.getElementById('whitelist').value = data.whitelist.join('\n');
    });

    // Save API Key
    document.getElementById('save-key').addEventListener('click', () => {
        const key = document.getElementById('api-key').value.trim();
        chrome.storage.sync.set({ apiKey: key }, () => {
            const status = document.getElementById('key-status');
            status.textContent = 'Key saved securely!';
            status.className = 'status success';
            setTimeout(() => status.textContent = '', 2000);
        });
    });

    // Save Prefs
    document.getElementById('save-prefs').addEventListener('click', () => {
        const sens = document.getElementById('sensitivity').value;
        const block = document.getElementById('auto-block').checked;
        const notifs = document.getElementById('notifications').checked;
        const wl = document.getElementById('whitelist').value.split('\n').map(s => s.trim()).filter(s => s);

        chrome.storage.sync.set({
            sensitivity: sens,
            autoBlock: block,
            notificationsEnabled: notifs,
            whitelist: wl
        }, () => {
            const status = document.getElementById('prefs-status');
            status.textContent = 'Preferences updated!';
            status.className = 'status success';
            setTimeout(() => status.textContent = '', 2000);
        });
    });

    // Clear Cache
    document.getElementById('clear-cache').addEventListener('click', async () => {
        if (confirm("Are you sure you want to clear the analysis cache?")) {
            const dbReq = indexedDB.deleteDatabase('scamguard-cache');
            dbReq.onsuccess = () => alert("Cache cleared successfully. It will be rebuilt on next page visit.");
            dbReq.onerror = () => alert("Failed to clear cache. Try again.");
        }
    });
});

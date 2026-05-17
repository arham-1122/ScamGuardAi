class Cache {
    constructor() {
        this.dbName = 'scamguard-cache';
        this.storeName = 'verdicts';
        this.version = 1;
        this.ttl = 24 * 60 * 60 * 1000; // 24 hours
    }

    async _openDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);

            request.onerror = () => reject(request.error);

            request.onsuccess = () => {
                const db = request.result;
                this._autoPurge(db);
                resolve(db);
            };

            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    db.createObjectStore(this.storeName);
                }
            };
        });
    }

    async _hashDomain(domainUrl) {
        const encoder = new TextEncoder();
        const data = encoder.encode(domainUrl);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    async _autoPurge(db) {
        try {
            const transaction = db.transaction(this.storeName, 'readwrite');
            const store = transaction.objectStore(this.storeName);
            const request = store.getAllKeys();

            request.onsuccess = () => {
                const keys = request.result;
                const now = Date.now();
                const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days

                keys.forEach(key => {
                    const getReq = store.get(key);
                    getReq.onsuccess = () => {
                        if (getReq.result && (now - getReq.result.timestamp > maxAge)) {
                            store.delete(key);
                        }
                    };
                });
            };
        } catch (e) {
            console.warn('Auto-purge failed', e);
        }
    }

    async get(domain) {
        const hash = await this._hashDomain(domain);
        const db = await this._openDB();

        return new Promise((resolve, reject) => {
            const transaction = db.transaction(this.storeName, 'readonly');
            const store = transaction.objectStore(this.storeName);
            const request = store.get(hash);

            request.onsuccess = () => {
                const result = request.result;
                if (!result) {
                    resolve(null);
                    return;
                }

                const now = Date.now();
                if (now - result.timestamp > this.ttl) {
                    // Cache expired
                    resolve(null);
                } else {
                    resolve(result.verdict);
                }
            };
            request.onerror = () => reject(request.error);
        });
    }

    async set(domain, verdict) {
        const hash = await this._hashDomain(domain);
        const db = await this._openDB();

        const entry = {
            verdict: verdict,
            timestamp: Date.now(),
            version: this.version
        };

        return new Promise((resolve, reject) => {
            const transaction = db.transaction(this.storeName, 'readwrite');
            const store = transaction.objectStore(this.storeName);
            const request = store.put(entry, hash);

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    async clear() {
        const db = await this._openDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(this.storeName, 'readwrite');
            const store = transaction.objectStore(this.storeName);
            const request = store.clear();

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }
}

export const CacheEngine = new Cache();

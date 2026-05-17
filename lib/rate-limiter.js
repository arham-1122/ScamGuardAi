export const RateLimiter = {
    capacity: 5, // A capacity of 5 enforces a strict burst cap of exactly 5
    refillRateMs: 3000, // 3 seconds per token (20 tokens per minute steady state)
    stateKey: 'scamguard-ratelimit',

    _memoryState: null,

    async _getState() {
        if (this._memoryState) return this._memoryState;
        const data = await chrome.storage.session.get(this.stateKey);
        this._memoryState = data[this.stateKey] || { tokens: this.capacity, lastRefill: Date.now() };
        return this._memoryState;
    },

    _saveState(state) {
        this._memoryState = state;
        // Push async without blocking the memory update to solve race conditions
        chrome.storage.session.set({ [this.stateKey]: state });
    },

    async _refill() {
        let state = await this._getState();
        const now = Date.now();
        const timePassed = now - state.lastRefill;
        const tokensToAdd = Math.floor(timePassed / this.refillRateMs);

        if (tokensToAdd > 0) {
            state.tokens = Math.min(this.capacity, state.tokens + tokensToAdd);
            state.lastRefill = state.lastRefill + (tokensToAdd * this.refillRateMs);
            this._saveState(state);
        }
        return state;
    },

    async consume() {
        let state = await this._refill();

        if (state.tokens >= 1) {
            state.tokens -= 1;
            this._saveState(state);
            return true;
        }

        return false;
    },

    async status() {
        const state = await this._refill();
        const nextRefillMs = state.tokens < this.capacity
            ? this.refillRateMs - (Date.now() - state.lastRefill)
            : 0;

        return {
            tokens: state.tokens,
            nextRefillMs: Math.max(0, nextRefillMs)
        };
    }
};

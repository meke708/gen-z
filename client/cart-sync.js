(() => {
    const cartKey = "z_cart";
    const ownerKey = "z_cart_owner";
    const maximumProducts = 20;
    let ownerId = "";
    let initialization;
    let saveTimer = null;
    let saveVersion = 0;
    let savedVersion = 0;
    let saving = false;

    async function request(url, options = {}) {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 8000);
        try {
            return await fetch(url, { ...options, signal: controller.signal });
        } finally {
            window.clearTimeout(timeout);
        }
    }

    function normalize(items) {
        if (!Array.isArray(items)) return [];
        const quantities = new Map();
        for (const item of items) {
            if (typeof item?.id !== "string" || !Number.isInteger(item.quantity) || item.quantity < 1) continue;
            const id = item.id.toLowerCase();
            const quantity = Math.min(99, (quantities.get(id) || 0) + item.quantity);
            if (quantities.has(id)) {
                quantities.set(id, quantity);
            } else if (quantities.size < maximumProducts) {
                quantities.set(id, quantity);
            }
        }
        return [...quantities].map(([id, quantity]) => ({ id, quantity }));
    }

    function readLocalCart() {
        try {
            return normalize(JSON.parse(localStorage.getItem(cartKey) || "[]"));
        } catch (error) {
            console.warn("Could not read the local cart:", error);
            return [];
        }
    }

    function announceCartChange() {
        window.dispatchEvent(new CustomEvent("z-cart-updated"));
    }

    function writeLocalCart(items) {
        try {
            localStorage.setItem(cartKey, JSON.stringify(items));
            announceCartChange();
        } catch (error) {
            console.error("Could not save the cart on this device:", error);
        }
    }

    async function flushSaveQueue() {
        if (!ownerId || saving || savedVersion === saveVersion) return;
        saving = true;
        try {
            while (savedVersion !== saveVersion) {
                const version = saveVersion;
                const items = readLocalCart();
                const response = await request("/api/account/cart", {
                    method: "PUT",
                    keepalive: true,
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ items })
                });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || "Could not sync your cart.");
                savedVersion = version;
            }
        } catch (error) {
            console.error("Cart synchronization failed; your local cart is still available:", error);
        } finally {
            saving = false;
        }
    }

    function scheduleSave() {
        if (!ownerId) return;
        saveVersion += 1;
        window.clearTimeout(saveTimer);
        saveTimer = window.setTimeout(() => void flushSaveQueue(), 400);
    }

    function mergeCarts(primaryItems, secondaryItems) {
        const quantities = new Map();
        for (const item of [...normalize(primaryItems), ...normalize(secondaryItems)]) {
            quantities.set(item.id, Math.max(quantities.get(item.id) || 0, item.quantity));
        }
        return normalize([...quantities].map(([id, quantity]) => ({ id, quantity })));
    }

    function initialize() {
        if (initialization) return initialization;
        initialization = (async () => {
            try {
                const statusResponse = await request("/api/auth/status");
                const status = await statusResponse.json();
                if (!statusResponse.ok) throw new Error(status.error || "Could not check your account.");
                if (!status.user) {
                    ownerId = "";
                    return;
                }

                const cartResponse = await request("/api/account/cart");
                const accountCart = await cartResponse.json();
                if (!cartResponse.ok) throw new Error(accountCart.error || "Could not load your saved cart.");

                const savedOwnerId = localStorage.getItem(ownerKey) || "";
                const localItems = savedOwnerId && savedOwnerId !== status.user.id ? [] : readLocalCart();
                const merged = savedOwnerId === status.user.id
                    ? normalize(accountCart.items || [])
                    : mergeCarts(accountCart.items || [], localItems);
                ownerId = status.user.id;
                localStorage.setItem(ownerKey, ownerId);
                writeLocalCart(merged);

                if (JSON.stringify(merged) !== JSON.stringify(normalize(accountCart.items || []))) {
                    saveVersion += 1;
                    await flushSaveQueue();
                } else {
                    savedVersion = saveVersion;
                }
            } catch (error) {
                initialization = null;
                console.error("Could not initialize cart synchronization:", error);
            }
        })();
        return initialization;
    }

    function saveCart(items) {
        const normalized = normalize(items);
        writeLocalCart(normalized);
        scheduleSave();
        return normalized;
    }

    window.addEventListener("storage", (event) => {
        if (event.key !== cartKey) return;
        announceCartChange();
        scheduleSave();
    });

    window.ZCartSync = {
        initialize,
        readCart: readLocalCart,
        saveCart,
        mergeCarts
    };
})();

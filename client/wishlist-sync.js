(() => {
    const wishlistKey = "z_wishlist";
    const ownerKey = "z_wishlist_owner";
    const maximumProducts = 500;
    let ownerId = "";
    let initialization;
    let saveTimer = null;
    let saveVersion = 0;
    let savedVersion = 0;
    let saving = false;
    let wishlistVersion = 0;
    let mutationQueue = Promise.resolve();

    function normalize(ids) {
        if (!Array.isArray(ids)) return [];
        return [...new Set(ids
            .filter((id) => typeof id === "string" && /^[a-f\d]{24}$/i.test(id))
            .map((id) => id.toLowerCase()))]
            .slice(0, maximumProducts);
    }

    function readLocalWishlist() {
        try {
            return normalize(JSON.parse(localStorage.getItem(wishlistKey) || "[]"));
        } catch (error) {
            console.warn("Could not read the local wishlist:", error);
            return [];
        }
    }

    function announceWishlistChange() {
        window.dispatchEvent(new CustomEvent("z-wishlist-updated"));
    }

    function writeLocalWishlist(ids) {
        try {
            localStorage.setItem(wishlistKey, JSON.stringify(ids));
            announceWishlistChange();
        } catch (error) {
            console.error("Could not save your wishlist on this device:", error);
        }
    }

    async function request(url, options = {}) {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 8000);
        try {
            return await fetch(url, { ...options, signal: controller.signal });
        } finally {
            window.clearTimeout(timeout);
        }
    }

    async function flushSaveQueue() {
        if (!ownerId || saving || savedVersion === saveVersion) return;
        saving = true;
        try {
            while (savedVersion !== saveVersion) {
                const version = saveVersion;
                const response = await request("/api/account/wishlist", {
                    method: "PUT",
                    keepalive: true,
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ ids: readLocalWishlist() })
                });
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || "Could not sync your wishlist.");
                savedVersion = version;
            }
        } catch (error) {
            console.error("Wishlist synchronization failed; your local wishlist is still available:", error);
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

    function syncToggle(id, saved, version) {
        if (!ownerId) return;
        const ownerAtRequest = ownerId;
        mutationQueue = mutationQueue.then(async () => {
            const response = await request(`/api/account/wishlist/${encodeURIComponent(id)}`, {
                method: saved ? "POST" : "DELETE"
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || "Could not sync your wishlist.");
            if (ownerId === ownerAtRequest && wishlistVersion === version) {
                writeLocalWishlist(normalize(result.ids || []));
            }
        }).catch((error) => {
            console.error("Wishlist update could not be synced; your local wishlist is still available:", error);
        });
    }

    function mergeWishlists(primaryIds, secondaryIds) {
        return normalize([...normalize(primaryIds), ...normalize(secondaryIds)]);
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

                const wishlistResponse = await request("/api/account/wishlist");
                const accountWishlist = await wishlistResponse.json();
                if (!wishlistResponse.ok) throw new Error(accountWishlist.error || "Could not load your wishlist.");

                const savedOwnerId = localStorage.getItem(ownerKey) || "";
                const localIds = savedOwnerId && savedOwnerId !== status.user.id ? [] : readLocalWishlist();
                const merged = savedOwnerId === status.user.id
                    ? normalize(accountWishlist.ids || [])
                    : mergeWishlists(accountWishlist.ids || [], localIds);
                ownerId = status.user.id;
                localStorage.setItem(ownerKey, ownerId);
                writeLocalWishlist(merged);

                if (JSON.stringify(merged) !== JSON.stringify(normalize(accountWishlist.ids || []))) {
                    saveVersion += 1;
                    await flushSaveQueue();
                } else {
                    savedVersion = saveVersion;
                }
            } catch (error) {
                initialization = null;
                console.error("Could not initialize wishlist synchronization:", error);
            }
        })();
        return initialization;
    }

    function saveWishlist(ids) {
        const normalized = normalize(ids);
        writeLocalWishlist(normalized);
        scheduleSave();
        return normalized;
    }

    function toggle(id) {
        const normalizedId = typeof id === "string" ? id.toLowerCase() : "";
        if (!/^[a-f\d]{24}$/.test(normalizedId)) throw new Error("This product cannot be added to your wishlist.");
        const ids = readLocalWishlist();
        const existingIndex = ids.indexOf(normalizedId);
        if (existingIndex >= 0) ids.splice(existingIndex, 1);
        else {
            if (ids.length >= maximumProducts) throw new Error(`Your wishlist can contain up to ${maximumProducts} products.`);
            ids.push(normalizedId);
        }
        const saved = existingIndex < 0;
        wishlistVersion += 1;
        const normalized = normalize(ids);
        writeLocalWishlist(normalized);
        syncToggle(normalizedId, saved, wishlistVersion);
        return { saved, ids: normalized };
    }

    window.addEventListener("storage", (event) => {
        if (event.key !== wishlistKey) return;
        wishlistVersion += 1;
        announceWishlistChange();
        scheduleSave();
    });

    window.ZWishlistSync = {
        initialize,
        readWishlist: readLocalWishlist,
        saveWishlist,
        mergeWishlists,
        has: (id) => readLocalWishlist().includes(typeof id === "string" ? id.toLowerCase() : ""),
        toggle,
        maximumProducts
    };
})();

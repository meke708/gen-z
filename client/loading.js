(() => {
    const originalFetch = window.fetch;
    let activeRequests = 0;
    let domReady = document.readyState !== "loading";
    let overlay;
    let shownAt = 0;
    let idleTimer;
    let maximumWaitTimer;
    let failedRequests = 0;
    const pageLabel = (() => {
        const path = window.location.pathname.replace(/\/+$/, "") || "/";
        if (path === "/" || path === "/marketplace") return "marketplace listings";
        if (path === "/shops") return "shop listings";
        if (path.startsWith("/shop/")) return "shop details";
        if (path.startsWith("/product/")) return "product details";
        if (path === "/dashboard") return "your account and orders";
        if (path === "/cart") return "your cart";
        if (path === "/checkout") return "checkout details";
        if (path === "/sell/profile") return "your seller profile";
        if (path === "/sell/verification") return "business verification status";
        if (path === "/sell/assistant") return "your shop assistant settings";
        if (path === "/sell/dashboard" || path === "/sell") return "your seller dashboard";
        if (path === "/admin/kyc") return "verification submissions";
        if (path === "/admin/support") return "support requests";
        if (path === "/admin/payouts") return "payout information";
        if (path === "/admin/moderation") return "listing reports";
        return "page content";
    })();

    function updateMessage() {
        if (!overlay) return;
        const message = overlay.querySelector(".page-loader-message");
        if (activeRequests) {
            message.textContent = `Loading ${pageLabel}...`;
        } else if (failedRequests) {
            message.textContent = `Some ${pageLabel} could not be loaded.`;
        } else {
            message.textContent = `${pageLabel[0].toUpperCase()}${pageLabel.slice(1)} loaded.`;
        }
    }

    function hideOverlay() {
        if (!overlay || overlay.classList.contains("is-hidden")) return;
        window.clearTimeout(maximumWaitTimer);
        const remainingMinimumTime = Math.max(0, 450 - (performance.now() - shownAt));
        maximumWaitTimer = window.setTimeout(() => {
            if (activeRequests) return;
            overlay.classList.add("is-hidden");
            overlay.setAttribute("aria-hidden", "true");
            window.setTimeout(() => overlay.remove(), 400);
        }, remainingMinimumTime);
    }

    function scheduleHide() {
        window.clearTimeout(idleTimer);
        if (domReady && activeRequests === 0 && overlay) {
            idleTimer = window.setTimeout(hideOverlay, 250);
        }
    }

    function showOverlay() {
        if (overlay || !document.body) return;
        overlay = document.createElement("div");
        overlay.className = "page-loader";
        overlay.setAttribute("role", "status");
        overlay.setAttribute("aria-live", "polite");
        overlay.innerHTML = '<div class="page-loader-content"><span class="page-loader-mark" aria-hidden="true">Z</span><p class="page-loader-message"></p><span class="page-loader-dots" aria-hidden="true"><span></span><span></span><span></span></span></div>';
        document.body.append(overlay);
        shownAt = performance.now();
        updateMessage();
        maximumWaitTimer = window.setTimeout(() => {
            failedRequests += 1;
            activeRequests = 0;
            updateMessage();
            hideOverlay();
        }, 8000);
    }

    function finishRequest(succeeded) {
        if (!succeeded) failedRequests += 1;
        activeRequests = Math.max(0, activeRequests - 1);
        updateMessage();
        scheduleHide();
    }

    window.fetch = function (...args) {
        const shouldTrack = !domReady || (overlay && !overlay.classList.contains("is-hidden"));
        if (shouldTrack) {
            window.clearTimeout(idleTimer);
            activeRequests += 1;
            showOverlay();
            updateMessage();
        }

        let request;
        try {
            request = originalFetch.apply(this, args);
        } catch (error) {
            if (shouldTrack) finishRequest(false);
            throw error;
        }

        if (shouldTrack) {
            request.then(
                (response) => finishRequest(response.ok),
                () => finishRequest(false)
            );
        }
        return request;
    };

    function markDomReady() {
        domReady = true;
        scheduleHide();
    }

    if (domReady) {
        scheduleHide();
    } else {
        document.addEventListener("DOMContentLoaded", markDomReady, { once: true });
    }
})();

(() => {
    const originalFetch = window.fetch;
    let activeRequests = 0;
    let domReady = document.readyState !== "loading";
    let overlay;
    let shownAt = 0;
    let showTimer;
    let idleTimer;
    let maximumWaitTimer;
    let removalTimer;
    let adminHeaderObserver;
    const isAdminPage = window.location.pathname.startsWith("/admin/");

    function positionAdminOverlay() {
        if (!isAdminPage || !overlay) return;
        const header = document.querySelector(".site-header");
        if (!header) return;

        const isCompactLayout = window.matchMedia("(max-width: 900px)").matches;
        if (isCompactLayout) {
            overlay.style.left = "0px";
            overlay.style.top = `${header.getBoundingClientRect().bottom}px`;
        } else {
            overlay.style.removeProperty("left");
            overlay.style.removeProperty("top");
        }
        if (!adminHeaderObserver && window.ResizeObserver) {
            adminHeaderObserver = new ResizeObserver(positionAdminOverlay);
            adminHeaderObserver.observe(header);
        }
    }

    function getDestinationLabel() {
        const title = document.title.split("|", 1)[0].trim();
        if (title) return title;

        const route = window.location.pathname.replace(/\/+$/, "").split("/").pop();
        return route ? route.replace(/[-_]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()) : "Home";
    }

    function hideOverlay() {
        if (!overlay || overlay.classList.contains("is-hidden")) return;
        window.clearTimeout(maximumWaitTimer);
        const minimumDisplayTime = isAdminPage ? 800 : 450;
        const remainingMinimumTime = Math.max(0, minimumDisplayTime - (performance.now() - shownAt));
        maximumWaitTimer = window.setTimeout(() => {
            if (activeRequests) return;
            overlay.classList.add("is-hidden");
            overlay.setAttribute("aria-hidden", "true");
            removalTimer = window.setTimeout(() => {
                if (!overlay?.classList.contains("is-hidden")) return;
                overlay.remove();
                overlay = null;
            }, 400);
        }, remainingMinimumTime);
    }

    function scheduleHide() {
        window.clearTimeout(idleTimer);
        if (domReady && activeRequests === 0 && overlay) {
            idleTimer = window.setTimeout(hideOverlay, 250);
        }
    }

    function scheduleShow() {
        if (!isAdminPage) {
            showOverlay();
            return;
        }
        if (overlay && !overlay.classList.contains("is-hidden")) return;
        if (showTimer) return;
        showTimer = window.setTimeout(() => {
            showTimer = null;
            if (activeRequests > 0) showOverlay();
        }, 400);
    }

    function showOverlay() {
        if (!document.body) return;
        if (overlay) {
            if (!overlay.classList.contains("is-hidden")) return;
            window.clearTimeout(removalTimer);
            overlay.classList.remove("is-hidden");
            overlay.setAttribute("aria-hidden", "false");
        } else {
            overlay = document.createElement("div");
            overlay.className = "page-loader";
            if (isAdminPage) overlay.classList.add("page-loader-admin");
            overlay.setAttribute("role", "status");
            overlay.setAttribute("aria-label", "Loading");
            overlay.setAttribute("aria-live", "polite");
            overlay.innerHTML = '<div class="page-loader-content"><span class="page-loader-mark" aria-hidden="true">Z</span><span class="page-loader-dots" aria-hidden="true"><span></span><span></span><span></span></span><p class="page-loader-message"></p></div>';
            overlay.querySelector(".page-loader-message").textContent = `Loading ${getDestinationLabel()}...`;
            document.body.append(overlay);
        }
        positionAdminOverlay();
        shownAt = performance.now();
        maximumWaitTimer = window.setTimeout(() => {
            activeRequests = 0;
            hideOverlay();
        }, 8000);
    }

    function finishRequest() {
        activeRequests = Math.max(0, activeRequests - 1);
        if (activeRequests === 0) {
            window.clearTimeout(showTimer);
            showTimer = null;
        }
        scheduleHide();
    }

    window.fetch = function (...args) {
        const shouldTrack = isAdminPage || !domReady || (overlay && !overlay.classList.contains("is-hidden"));
        if (shouldTrack) {
            window.clearTimeout(idleTimer);
            activeRequests += 1;
            scheduleShow();
        }

        let request;
        try {
            request = originalFetch.apply(this, args);
        } catch (error) {
            if (shouldTrack) finishRequest();
            throw error;
        }

        if (shouldTrack) {
            request.then(
                finishRequest,
                finishRequest
            );
        }
        return request;
    };

    function markDomReady() {
        domReady = true;
        if (isAdminPage && activeRequests) scheduleShow();
        positionAdminOverlay();
        scheduleHide();
    }

    if (domReady) {
        positionAdminOverlay();
        scheduleHide();
    } else {
        document.addEventListener("DOMContentLoaded", markDomReady, { once: true });
    }
    window.addEventListener("resize", positionAdminOverlay);
})();

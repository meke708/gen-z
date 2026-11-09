(() => {
    let visitorId = "";
    const observedElements = new WeakSet();
    const sentEvents = new Set();

    function getVisitorId() {
        if (visitorId) return visitorId;
        try {
            visitorId = window.sessionStorage.getItem("z-promotion-visitor") || "";
        } catch (error) {
            console.warn("Promotion analytics could not access session storage:", error);
        }
        if (!visitorId) {
            const bytes = new Uint8Array(16);
            window.crypto.getRandomValues(bytes);
            visitorId = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
            try {
                window.sessionStorage.setItem("z-promotion-visitor", visitorId);
            } catch (error) {
                console.warn("Promotion analytics could not persist its session ID:", error);
            }
        }
        return visitorId;
    }

    function track(campaignId, eventType, placement) {
        if (!campaignId) return;
        const eventKey = `${campaignId}:${eventType}:${placement}:${new Date().toISOString().slice(0, 10)}`;
        if (sentEvents.has(eventKey)) return;
        sentEvents.add(eventKey);
        fetch(`/api/promotions/${encodeURIComponent(campaignId)}/engagement`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ visitorId: getVisitorId(), eventType, placement }),
            keepalive: true
        }).then((response) => {
            if (!response.ok) console.warn(`Promotion ${eventType} tracking was rejected (${response.status}).`);
        }).catch((error) => {
            console.warn(`Promotion ${eventType} tracking failed:`, error);
        });
    }

    function observeImpression(element, campaignId, placement) {
        if (!element || !campaignId || observedElements.has(element)) return;
        observedElements.add(element);
        let isVisible = false;
        let observer;
        const handleVisibilityChange = () => {
            if (document.visibilityState !== "visible") {
                isVisible = false;
                return;
            }
            observer?.unobserve(element);
            observer?.observe(element);
        };
        const recordImpressionWhenVisible = () => {
            if (isVisible && document.visibilityState === "visible") {
                observer?.disconnect();
                document.removeEventListener("visibilitychange", handleVisibilityChange);
                track(campaignId, "impression", placement);
            }
        };
        if ("IntersectionObserver" in window) {
            observer = new IntersectionObserver((entries) => {
                const entry = entries[0];
                isVisible = Boolean(entry?.isIntersecting && entry.intersectionRatio >= 0.5);
                recordImpressionWhenVisible();
            }, { threshold: 0.5 });
            observer.observe(element);
            document.addEventListener("visibilitychange", handleVisibilityChange);
            return;
        }

        const bounds = element.getBoundingClientRect();
        const visibleWidth = Math.max(0, Math.min(bounds.right, window.innerWidth) - Math.max(bounds.left, 0));
        const visibleHeight = Math.max(0, Math.min(bounds.bottom, window.innerHeight) - Math.max(bounds.top, 0));
        isVisible = bounds.width > 0 && bounds.height > 0
            && (visibleWidth * visibleHeight) / (bounds.width * bounds.height) >= 0.5;
        recordImpressionWhenVisible();
    }

    function trackClick(element, campaignId, placement) {
        element?.addEventListener("click", () => track(campaignId, "click", placement));
    }

    window.ZPromotionAnalytics = { observeImpression, trackClick };
})();

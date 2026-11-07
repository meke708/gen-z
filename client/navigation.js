(() => {
    const stylesheet = document.createElement("link");
    stylesheet.rel = "stylesheet";
    stylesheet.href = "/navigation.css";
    document.head.append(stylesheet);

    const cartLink = document.querySelector(".cart-icon-link");
    const cartCount = cartLink?.querySelector(".cart-count");
    if (cartLink && cartCount) {
        const updateCartCount = () => {
            try {
                const cart = JSON.parse(localStorage.getItem("z_cart") || "[]");
                const count = Array.isArray(cart)
                    ? cart.reduce((total, item) => total + (Number.isInteger(item.quantity) && item.quantity > 0 ? item.quantity : 0), 0)
                    : 0;
                cartCount.textContent = String(count);
                cartLink.setAttribute("aria-label", `View cart, ${count} ${count === 1 ? "item" : "items"}`);
            } catch {
                cartCount.textContent = "0";
                cartLink.setAttribute("aria-label", "View cart, 0 items");
            }
        };
        updateCartCount();
        window.addEventListener("storage", (event) => {
            if (event.key === "z_cart") updateCartCount();
        });
        window.addEventListener("focus", updateCartCount);
    }

    const header = document.querySelector(".site-header");
    const nav = header?.querySelector("nav");
    if (!header || !nav) return;

    const path = window.location.pathname.replace(/\/+$/, "") || "/";
    const wideLayouts = [
        ["/", "layout-marketplace"],
        ["/marketplace", "layout-marketplace"],
        ["/shops", "layout-shops"],
        ["/cart", "layout-cart"],
        ["/checkout", "layout-checkout"],
        ["/dashboard", "layout-dashboard"]
    ];
    const wideLayout = wideLayouts.find(([route]) => path === route);
    const isShopPage = path.startsWith("/shop/");
    const isProductPage = path.startsWith("/product/");
    const isSellerDashboard = path === "/sell/dashboard";
    const isAdminPage = path.startsWith("/admin/");
    if (wideLayout || isShopPage || isProductPage || isSellerDashboard || isAdminPage) {
        document.body.classList.add("layout-wide");
        if (wideLayout) document.body.classList.add(wideLayout[1]);
        if (isShopPage) document.body.classList.add("layout-shop");
        if (isProductPage) document.body.classList.add("layout-product");
        if (isSellerDashboard) document.body.classList.add("layout-seller");
        if (isAdminPage) document.body.classList.add("layout-admin");

        const layoutStylesheet = document.createElement("link");
        layoutStylesheet.rel = "stylesheet";
        layoutStylesheet.href = "/wide-layout.css";
        document.head.append(layoutStylesheet);
    }
    if (path === "/" || path === "/marketplace") {
        document.documentElement.classList.add("hide-scrollbar");
    }

    const routes = path === "/" ? ["/marketplace"]
        : path.startsWith("/product/") ? ["/marketplace"]
        : path.startsWith("/shop/") ? ["/shops"]
            : path === "/checkout" ? ["/cart"]
                : [path];

    const normalizeHref = (anchor) => {
        try {
            return new URL(anchor.href, window.location.origin).pathname.replace(/\/+$/, "") || "/";
        } catch {
            return "";
        }
    };

    const setNavLabel = (anchor, label) => {
        const firstText = [...anchor.childNodes].find((node) => node.nodeType === Node.TEXT_NODE);
        if (firstText) firstText.nodeValue = ` ${label} `;
        else anchor.textContent = label;
    };

    const adminLinks = [
        ["/admin/moderation", "Moderation"],
        ["/admin/payouts", "Payouts"],
        ["/admin/kyc", "Business verification"],
        ["/admin/support", "Support"],
        ["/marketplace", "Marketplace"]
    ];
    const sellerLinks = [
        ["/sell/dashboard", "Seller dashboard"],
        ["/sell/profile", "Seller profile"],
        ["/sell/assistant", "Shop AI assistant"],
        ["/sell/verification", "Business verification"],
        ["/marketplace", "Marketplace"]
    ];

    const orderedLinks = path.startsWith("/admin/") ? adminLinks : path.startsWith("/sell") ? sellerLinks : [];
    for (const [href, label] of orderedLinks) {
        let anchor = [...nav.querySelectorAll("a")].find((candidate) => normalizeHref(candidate) === href);
        if (!anchor) {
            anchor = document.createElement("a");
            anchor.href = href;
            anchor.textContent = label;
        }
        nav.append(anchor);
    }

    let accountLink = [...nav.querySelectorAll("a")].find((anchor) => {
        const href = normalizeHref(anchor);
        return href === "/login" || href === "/dashboard" || anchor.hasAttribute("data-account-link");
    });

    if (!accountLink && !header.querySelector("#sign-out")) {
        accountLink = document.createElement("a");
        accountLink.href = "/dashboard";
        accountLink.dataset.accountLink = "";
        accountLink.textContent = "My account";
    }
    if (accountLink) nav.append(accountLink);

    for (const anchor of nav.querySelectorAll("a")) {
        const href = normalizeHref(anchor);
        if (href === "/marketplace") setNavLabel(anchor, "Marketplace");
        else if (href === "/shops") setNavLabel(anchor, "Shops");
        else if (href === "/dashboard") setNavLabel(anchor, "My account");
        else if (href === "/login") setNavLabel(anchor, "Sign in");

        if (routes.includes(href)) anchor.setAttribute("aria-current", "page");
        else anchor.removeAttribute("aria-current");
    }

    if (accountLink) {
        fetch("/api/auth/status")
            .then((response) => {
                if (!response.ok) throw new Error(`Account status request failed (${response.status}).`);
                return response.json();
            })
            .then(({ user }) => {
                accountLink.href = user ? "/dashboard" : "/login";
                setNavLabel(accountLink, user ? "My account" : "Sign in");
                if (routes.includes(normalizeHref(accountLink))) accountLink.setAttribute("aria-current", "page");
                else accountLink.removeAttribute("aria-current");
            })
            .catch((error) => console.error("Navigation account status could not be loaded:", error));
    }
})();

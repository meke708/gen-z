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
                const cart = window.ZCartSync?.readCart() || JSON.parse(localStorage.getItem("z_cart") || "[]");
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
        window.addEventListener("z-cart-updated", updateCartCount);
        window.addEventListener("focus", updateCartCount);
        const initializeCartSync = () => window.ZCartSync.initialize().then(updateCartCount);
        if (window.ZCartSync) {
            void initializeCartSync();
        } else {
            const cartSyncScript = document.createElement("script");
            cartSyncScript.src = "/cart-sync.js";
            cartSyncScript.onload = initializeCartSync;
            cartSyncScript.onerror = () => console.error("Could not load cart synchronization.");
            document.head.append(cartSyncScript);
        }
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
    const isShopPage = path.startsWith("/shop/") || path.startsWith("/shops/");
    const isProductPage = path.startsWith("/product/");
    const isSellerPortal = path === "/sell" || path.startsWith("/sell/");
    const isAdminPage = path.startsWith("/admin/");
    if (isAdminPage) {
        const brand = header.querySelector(".brand");
        if (brand) {
            let headerLeft = header.querySelector(".header-left");
            if (!headerLeft) {
                headerLeft = document.createElement("div");
                headerLeft.className = "header-left";
                header.insertBefore(headerLeft, nav);
            }
            headerLeft.replaceChildren(brand);
            brand.href = "/admin/moderation";
        }
        nav.setAttribute("aria-label", "Administration navigation");
    }
    if (isSellerPortal) {
        const brand = header.querySelector(".brand");
        if (brand) {
            let headerLeft = header.querySelector(".header-left");
            if (!headerLeft) {
                headerLeft = document.createElement("div");
                headerLeft.className = "header-left";
                header.insertBefore(headerLeft, nav);
            }
            headerLeft.append(brand);
            brand.href = "/marketplace";
        }
        nav.setAttribute("aria-label", "Seller navigation");
    }
    if (wideLayout || isShopPage || isProductPage || isSellerPortal || isAdminPage) {
        document.body.classList.add("layout-wide");
        if (wideLayout) document.body.classList.add(wideLayout[1]);
        if (isShopPage) document.body.classList.add("layout-shop");
        if (isProductPage) document.body.classList.add("layout-product");
        if (isSellerPortal) document.body.classList.add("layout-seller");
        if (isAdminPage) document.body.classList.add("layout-admin");

        const layoutStylesheet = document.createElement("link");
        layoutStylesheet.rel = "stylesheet";
        layoutStylesheet.href = "/wide-layout.css";
        document.head.append(layoutStylesheet);
        if (isAdminPage) {
            const adminStylesheet = document.createElement("link");
            adminStylesheet.rel = "stylesheet";
            adminStylesheet.href = "/admin-shell.css";
            document.head.append(adminStylesheet);
        } else if (isSellerPortal) {
            const sellerStylesheet = document.createElement("link");
            sellerStylesheet.rel = "stylesheet";
            sellerStylesheet.href = "/seller-shell.css";
            document.head.append(sellerStylesheet);
        }
    }
    if (path === "/" || path === "/marketplace" || path === "/dashboard") {
        document.documentElement.classList.add("hide-scrollbar");
    }

    const routes = path.startsWith("/admin/accounts/") ? ["/admin/accounts"]
        : path === "/" ? ["/marketplace"]
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
        const labelElement = anchor.querySelector(".account-link-label");
        if (labelElement) {
            labelElement.textContent = label;
            return;
        }
        const firstText = [...anchor.childNodes].find((node) => node.nodeType === Node.TEXT_NODE);
        if (firstText) firstText.nodeValue = ` ${label} `;
        else anchor.textContent = label;
    };

    const createSellerAvatar = () => {
        const identity = document.createElement("div");
        identity.className = "seller-account-identity";
        const link = document.createElement("a");
        link.className = "seller-account-avatar-link";
        link.href = "/sell/profile";
        link.setAttribute("aria-label", "Open business profile");
        const verificationWarning = document.createElement("span");
        verificationWarning.className = "seller-account-verification-warning";
        verificationWarning.textContent = "!";
        verificationWarning.setAttribute("role", "img");
        verificationWarning.setAttribute("aria-label", "Business not verified");
        verificationWarning.hidden = true;
        const avatar = document.createElement("span");
        avatar.className = "seller-account-avatar";
        avatar.setAttribute("role", "img");
        avatar.setAttribute("aria-label", "Business profile photo");
        const fallback = document.createElement("span");
        fallback.className = "seller-account-avatar-fallback";
        fallback.textContent = "Z";
        const image = document.createElement("img");
        image.alt = "";
        image.hidden = true;
        image.addEventListener("load", () => {
            image.hidden = false;
            fallback.hidden = true;
        });
        image.addEventListener("error", () => {
            image.hidden = true;
            fallback.hidden = false;
        });
        avatar.append(image, fallback, verificationWarning);
        link.append(avatar);
        const businessName = document.createElement("span");
        businessName.className = "seller-account-business-name";
        identity.append(link, businessName);
        return { identity, link, fallback, image, businessName, verificationWarning };
    };

    const adminLinks = [
        ["/admin/moderation", "Moderation"],
        ["/admin/login-wallpaper", "Login wallpaper"],
        ["/marketplace", "Marketplace"]
    ];
    const superAdminLinks = [
        ["/admin/payouts", "Payouts"],
        ["/admin/kyc", "Business verification"],
        ["/admin/support", "Support"],
        ["/admin/accounts", "User accounts"],
        ["/admin/notifications", "Notifications"],
        ["/admin/platform", "Platform controls"],
        ["/admin/server-config", "Server configurations"],
        ["/admin/commands", "Commands"],
        ["/admin/statement-verification", "Verify statements"],
    ];
    const sellerLinks = [
        ["/sell/dashboard", "Dashboard"],
        ["/sell/orders", "Manage orders"],
        ["/sell/listings", "Manage listings"],
        ["/sell/notifications", "Updates"],
        ["/sell/transactions", "Transactions"],
        ["/sell/billing", "Billing"],
        ["/sell/assistant", "Shop AI assistant"],
        ["/sell/profile", "Business profile"],
        ["/sell/verification", "Business verification"],
        ["/support", "Help & support"],
        ["/marketplace", "Marketplace"],
        ["/dashboard", "Buyer's account"]
    ];

    const orderedLinks = path.startsWith("/admin/") ? adminLinks : isSellerPortal ? sellerLinks : [];
    if (isSellerPortal) nav.replaceChildren();
    for (const [href, label] of orderedLinks) {
        let anchor = [...nav.querySelectorAll("a")].find((candidate) => normalizeHref(candidate) === href);
        if (!anchor) {
            anchor = document.createElement("a");
            anchor.href = href;
        }
        setNavLabel(anchor, label);
        if (isSellerPortal && href === "/sell/notifications") {
            anchor.classList.add("seller-updates-link");
            anchor.setAttribute("aria-label", "Seller updates");
            const badge = document.createElement("span");
            badge.className = "seller-updates-count";
            badge.id = "seller-notification-count";
            badge.setAttribute("aria-label", "Unread seller updates");
            badge.hidden = true;
            anchor.append(badge);
        }
        nav.append(anchor);
    }

    let accountLink = [...nav.querySelectorAll("a")].find((anchor) => {
        const href = normalizeHref(anchor);
        return href === "/login" || href === "/dashboard" || anchor.hasAttribute("data-account-link");
    });

    if (!accountLink && !header.querySelector("#sign-out") && !isSellerPortal) {
        accountLink = document.createElement("a");
        accountLink.href = "/dashboard";
        accountLink.dataset.accountLink = "";
        accountLink.textContent = "My account";
    }
    if (accountLink) nav.append(accountLink);
    if (isSellerPortal && path !== "/sell/notifications") {
        fetch("/api/account/notifications?workspace=seller")
            .then(async (response) => {
                const result = await response.json();
                if (!response.ok) throw new Error(result.error || "Could not load seller updates.");
                const badge = document.querySelector("#seller-notification-count");
                if (!badge) return;
                const unreadCount = Number(result.unreadCount) || 0;
                badge.hidden = unreadCount === 0;
                badge.textContent = unreadCount > 99 ? "99+" : String(unreadCount);
                badge.setAttribute("aria-label", `${unreadCount} unread seller update${unreadCount === 1 ? "" : "s"}`);
            })
            .catch((error) => console.error("Seller update count could not be loaded:", error));
    }
    const sellerAvatar = isSellerPortal ? createSellerAvatar() : null;
    if (sellerAvatar) {
        let avatarSlot = header.querySelector("#seller-avatar-slot");
        if (!avatarSlot) {
            let sellerActions = header.querySelector(".seller-header-actions");
            if (!sellerActions) {
                sellerActions = document.createElement("div");
                sellerActions.className = "seller-header-actions";
                header.append(sellerActions);
            }
            avatarSlot = document.createElement("span");
            avatarSlot.id = "seller-avatar-slot";
            sellerActions.prepend(avatarSlot);
        }
        avatarSlot.replaceChildren(sellerAvatar.identity);
    }

    const sellerMenuToggle = header.querySelector("#seller-mobile-nav-toggle");
    if (sellerMenuToggle) {
        const closeSellerMenu = () => {
            nav.classList.remove("is-open");
            sellerMenuToggle.setAttribute("aria-expanded", "false");
            sellerMenuToggle.setAttribute("aria-label", "Open seller navigation menu");
        };
        sellerMenuToggle.addEventListener("click", () => {
            const isOpen = nav.classList.toggle("is-open");
            sellerMenuToggle.setAttribute("aria-expanded", String(isOpen));
            sellerMenuToggle.setAttribute("aria-label", isOpen ? "Close seller navigation menu" : "Open seller navigation menu");
        });
        nav.addEventListener("click", (event) => {
            if (event.target.closest("a")) closeSellerMenu();
        });
        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape") closeSellerMenu();
        });
    }

    for (const anchor of nav.querySelectorAll("a")) {
        const href = normalizeHref(anchor);
        if (href === "/marketplace") setNavLabel(anchor, "Marketplace");
        else if (href === "/shops") setNavLabel(anchor, "Shops");
        else if (href === "/dashboard") setNavLabel(anchor, isSellerPortal ? "Buyer's account" : isAdminPage ? "User account" : "My account");
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
                setNavLabel(accountLink, user ? (isSellerPortal ? "Buyer's account" : isAdminPage ? "User account" : "My account") : "Sign in");
                if (routes.includes(normalizeHref(accountLink))) accountLink.setAttribute("aria-current", "page");
                else accountLink.removeAttribute("aria-current");
                if (path.startsWith("/admin/") && user?.isSuperAdmin) {
                    for (const [href, label] of superAdminLinks) {
                        let anchor = [...nav.querySelectorAll("a")].find((candidate) => normalizeHref(candidate) === href);
                        if (!anchor) {
                            anchor = document.createElement("a");
                            anchor.href = href;
                        }
                        setNavLabel(anchor, label);
                        if (routes.includes(href)) anchor.setAttribute("aria-current", "page");
                        nav.insertBefore(anchor, accountLink);
                    }
                }
            })
            .catch((error) => console.error("Navigation account status could not be loaded:", error));
    }

    if (sellerAvatar) {
        fetch("/api/auth/status")
            .then((response) => {
                if (!response.ok) throw new Error(`Account status request failed (${response.status}).`);
                return response.json();
            })
            .then(({ user }) => {
                if (!user) return;
                return fetch("/api/seller/shop")
                    .then((response) => {
                        if (!response.ok) throw new Error(`Seller shop request failed (${response.status}).`);
                        return response.json();
                    })
                    .then(({ shop }) => {
                        if (!shop) return;
                        sellerAvatar.businessName.textContent = shop.name || "Business profile";
                        sellerAvatar.link.setAttribute("aria-label", `Open ${shop.name || "business"} profile`);
                        sellerAvatar.fallback.textContent = shop.name?.trim()?.charAt(0)?.toLocaleUpperCase() || "?";
                        if (shop.kycStatus !== "verified") {
                            sellerAvatar.verificationWarning.hidden = false;
                            sellerAvatar.link.setAttribute("aria-label", `Open ${shop.name || "business"} profile. Business not verified.`);
                        }
                        if (typeof shop.coverImageUrl === "string" && shop.coverImageUrl.startsWith("https://")) {
                            sellerAvatar.image.src = shop.coverImageUrl;
                        }
                    });
            })
            .catch((error) => console.error("Seller business profile photo could not be loaded:", error));
    }
})();

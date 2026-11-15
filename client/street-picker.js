(() => {
    const ENDPOINT = "https://photon.komoot.io/api/";
    const MIN_QUERY_LENGTH = 2;
    const MAX_RESULTS = 20;
    const DEBOUNCE_MS = 500;
    const normalize = (value) => String(value || "").trim().replace(/\s+/g, " ").toLocaleLowerCase("en");
    const streetSearchText = (value) => String(value || "")
        .replace(/\b\d+(?:st|nd|rd|th)?[A-Za-z]?(?:[-/]\d+[A-Za-z]?)?\b/gi, " ")
        .replace(/\s+/g, " ")
        .trim();

    function attach(input, getTown, status) {
        const list = document.getElementById(input.getAttribute("aria-controls") || "");
        if (!list) throw new Error("Street suggestion list was not found.");

        let debounceTimer = null;
        let activeController = null;
        let requestVersion = 0;

        function cancelPendingSearch() {
            window.clearTimeout(debounceTimer);
            debounceTimer = null;
            requestVersion += 1;
            if (activeController) activeController.abort();
            activeController = null;
        }

        function hideSuggestions() {
            list.hidden = true;
            list.replaceChildren();
            input.setAttribute("aria-expanded", "false");
        }

        async function search(version) {
            const town = String(getTown() || "").trim();
            const query = streetSearchText(input.value);
            const queryWords = normalize(query).split(" ").filter(Boolean);
            const controller = new AbortController();
            activeController = controller;
            const params = new URLSearchParams({
                q: `${query}, ${town}, Namibia`,
                countrycode: "NA",
                layer: "street",
                limit: String(MAX_RESULTS),
                lang: "en"
            });

            try {
                const response = await fetch(`${ENDPOINT}?${params}`, {
                    headers: { Accept: "application/json" },
                    signal: controller.signal
                });
                if (!response.ok) throw new Error(`Street search returned HTTP ${response.status}.`);
                const result = await response.json();
                if (version !== requestVersion) return;
                if (!Array.isArray(result.features)) throw new Error("Street search returned invalid results.");

                const streets = new Map();
                for (const feature of result.features) {
                    const properties = feature && feature.properties;
                    if (!properties || String(properties.countrycode || "").toUpperCase() !== "NA" || properties.type !== "street"
                        || typeof properties.name !== "string" || !properties.name.trim()) continue;
                    const streetWords = normalize(properties.name).split(" ").filter(Boolean);
                    if (!queryWords.every((word) => streetWords.some((streetWord) => streetWord.startsWith(word)))) continue;
                    const locations = [properties.city, properties.locality, properties.district]
                        .filter((location) => typeof location === "string" && location.trim());
                    if (locations.length && !locations.some((location) => normalize(location) === normalize(town))) continue;
                    const name = properties.name.trim();
                    const key = normalize(name);
                    if (!streets.has(key)) streets.set(key, {
                        name,
                        label: properties.district ? `${name} — ${properties.district}` : name
                    });
                }

                list.replaceChildren(...Array.from(streets.values(), (street) => {
                    const button = document.createElement("button");
                    button.type = "button";
                    button.className = "street-suggestion";
                    button.textContent = street.label;
                    button.addEventListener("click", () => {
                        const addressNumbers = input.value.match(/\b\d+(?:st|nd|rd|th)?[A-Za-z]?(?:[-/]\d+[A-Za-z]?)?\b/gi) || [];
                        input.value = `${addressNumbers.join(" ")} ${street.name}`.trim();
                        hideSuggestions();
                        input.focus();
                        status.textContent = `${street.name} selected. Add a house number or unit if needed.`;
                        input.dispatchEvent(new Event("change", { bubbles: true }));
                    });
                    return button;
                }));
                list.hidden = streets.size === 0;
                input.setAttribute("aria-expanded", streets.size ? "true" : "false");
                status.textContent = streets.size
                    ? `${streets.size} mapped street suggestion${streets.size === 1 ? "" : "s"} found. Select one below or keep typing to narrow the list.`
                    : "No mapped street suggestions found. You can enter the address manually.";
            } catch (error) {
                if (error.name === "AbortError" || version !== requestVersion) return;
                status.textContent = "Street suggestions are unavailable. You can enter the address manually.";
                console.error("OpenStreetMap street suggestions could not be loaded:", error);
            } finally {
                if (activeController === controller) activeController = null;
            }
        }

        function refresh(searchForAddress = true) {
            cancelPendingSearch();
            hideSuggestions();
            const town = String(getTown() || "").trim();
            const query = streetSearchText(input.value);
            if (!town) {
                status.textContent = "Choose a business town before searching for streets.";
                return;
            }
            if (query.length < MIN_QUERY_LENGTH) {
                status.textContent = `Enter at least ${MIN_QUERY_LENGTH} letters to search mapped streets.`;
                return;
            }
            if (!searchForAddress) {
                status.textContent = "Edit the address to search for mapped street suggestions.";
                return;
            }
            status.textContent = "Searching OpenStreetMap street suggestions...";
            const version = requestVersion;
            debounceTimer = window.setTimeout(() => search(version), DEBOUNCE_MS);
        }

        input.addEventListener("input", refresh);
        input.addEventListener("keydown", (event) => {
            if (event.key === "ArrowDown" && !list.hidden) {
                event.preventDefault();
                list.querySelector("button")?.focus();
            } else if (event.key === "Escape" && !list.hidden) {
                hideSuggestions();
            }
        });
        refresh();
        return { refresh };
    }

    window.ZNamibiaStreetPicker = { attach };
})();

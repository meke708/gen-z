(() => {
    const OTHER_TOWN = "__other_town__";
    const normalize = (value) => String(value || "").trim().replace(/\s+/g, " ").toLocaleLowerCase("en");
    const getOtherInput = (select) => document.getElementById(select.dataset.otherInput || "");

    function updateOtherInput(select) {
        const input = getOtherInput(select);
        if (!input) return;
        const isOther = select.value === OTHER_TOWN;
        input.hidden = !isOther;
        input.style.display = isOther ? "block" : "none";
        input.required = isOther && input.dataset.required === "true";
        if (!isOther) input.value = "";
    }

    function setTown(select, value, dispatchChange = true) {
        if (!select.dataset.townPickerReady) {
            select.dataset.initialTown = value || "";
            return;
        }
        const town = String(value || "").trim();
        if (normalize(town) === "other") {
            select.value = "";
            updateOtherInput(select);
            return;
        }
        const option = Array.from(select.options).find((item) => item.value !== OTHER_TOWN && normalize(item.value) === normalize(town));
        if (option) {
            select.value = option.value;
        } else if (town && getOtherInput(select)) {
            select.value = OTHER_TOWN;
            getOtherInput(select).value = town;
        } else {
            select.value = "";
        }
        updateOtherInput(select);
        if (dispatchChange) select.dispatchEvent(new Event("change", { bubbles: true }));
    }

    async function populateTownPickers() {
        const selects = [...document.querySelectorAll("select[data-town-picker]")];
        if (!selects.length) return true;

        const response = await fetch("/namibian-towns.json");
        if (!response.ok) throw new Error("Could not load the town list.");
        const towns = await response.json();
        if (!Array.isArray(towns) || towns.some((town) => typeof town !== "string" || !town.trim())) {
            throw new Error("The town list is invalid.");
        }

        for (const select of selects) {
            const initialTown = select.dataset.initialTown || select.value;
            const emptyLabel = select.dataset.emptyLabel || select.options[0]?.textContent.trim() || "Choose a town";
            select.disabled = true;
            select.replaceChildren(new Option(emptyLabel, ""));
            towns.forEach((town) => select.add(new Option(town, town)));
            if (getOtherInput(select)) select.add(new Option("Other (enter town)", OTHER_TOWN));
            select.dataset.townPickerReady = "true";
            setTown(select, initialTown, false);
            select.disabled = false;
            select.addEventListener("change", () => updateOtherInput(select));
        }
        return true;
    }

    function showTownFallback(error) {
        console.error("Town suggestions are unavailable:", error);
        for (const select of document.querySelectorAll("select[data-town-picker]")) {
            const input = getOtherInput(select);
            const emptyLabel = select.dataset.emptyLabel || select.options[0]?.textContent.trim() || "Choose a town";
            const initialTown = select.dataset.initialTown || select.value;
            select.replaceChildren(new Option(emptyLabel, ""));
            if (input) {
                select.add(new Option("Other (enter town)", OTHER_TOWN));
                input.placeholder = "Town suggestions unavailable; enter your town";
            }
            select.dataset.townPickerReady = "true";
            setTown(select, initialTown, false);
            updateOtherInput(select);
            select.addEventListener("change", () => updateOtherInput(select));
            select.disabled = false;
            const errorMessage = document.getElementById(select.dataset.errorTarget || "");
            if (errorMessage) {
                errorMessage.textContent = "Town suggestions could not be loaded. You can enter your town manually.";
                errorMessage.hidden = false;
            }
        }
        return false;
    }

    window.ZNamibiaTownPicker = {
        ready: populateTownPickers().catch(showTownFallback),
        getValue(selectId) {
            const select = document.getElementById(selectId);
            if (!select) throw new Error(`Town selector "${selectId}" was not found.`);
            return select.value === OTHER_TOWN ? (getOtherInput(select)?.value || "").trim() : select.value;
        },
        setValue(selectId, value) {
            const select = document.getElementById(selectId);
            if (!select) throw new Error(`Town selector "${selectId}" was not found.`);
            setTown(select, value);
        }
    };
})();

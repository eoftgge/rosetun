// An old address redirects to the new page and keeps the part after "#".
// Without JavaScript the meta refresh in the page still leads to the page.
(() => {
    const script = document.currentScript;
    if (script && script.dataset.target) {
        location.replace(script.dataset.target + location.hash);
    }
})();

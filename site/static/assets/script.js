document.addEventListener("DOMContentLoaded", () => {
    const dialog = document.getElementById("image-lightbox");
    if (!dialog) return;

    const image = dialog.querySelector("img");
    const closeButton = dialog.querySelector(".lightbox-close");

    if (!image || !closeButton) return;

    document.querySelectorAll("a.screenshot").forEach(link => {
        link.addEventListener("click", event => {
            event.preventDefault();

            const thumbnail = link.querySelector("img");

            image.src = link.href;
            image.alt = thumbnail?.alt || "Screenshot";

            dialog.showModal();
        });
    });

    closeButton.addEventListener("click", () => {
        dialog.close();
    });

    dialog.addEventListener("click", event => {
        if (event.target === dialog) {
            dialog.close();
        }
    });

    dialog.addEventListener("close", () => {
        image.removeAttribute("src");
    });
});

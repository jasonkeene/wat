
function preloadImage(url) {
   (new Image()).src=url;
}

// add handlers for hover gifs
window.addEventListener("DOMContentLoaded", function() {
    var elements = document.querySelectorAll('.hover-gif');

    elements.forEach(function (element) {
        var gifSrc = element.getAttribute("data-animated-src");
        preloadImage(gifSrc);
        var originalSrc = element.getAttribute("src");

        element.addEventListener('mouseenter', function (e) {
            e.target.setAttribute("src", gifSrc);
        });

        element.addEventListener('mouseleave', function (e) {
            e.target.setAttribute("src", originalSrc);
        });
    });
}, false);

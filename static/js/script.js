document.addEventListener("DOMContentLoaded", function () {

    /* =========================
       MODULE BUTTON FEEDBACK
    ========================= */

    const buttons = document.querySelectorAll(".module-btn");

    buttons.forEach(function (button) {

        button.addEventListener("click", function () {

            button.style.opacity = "0.7";

        });

    });


    /* =========================
       NAVBAR SCROLL BEHAVIOR
    ========================= */

    const navbar = document.querySelector(".navbar");

    if (!navbar) return;

    let lastScrollY = window.scrollY;
    let scrollTimer;


    window.addEventListener("scroll", function () {

        const currentScrollY = window.scrollY;

        clearTimeout(scrollTimer);


        /* At the top */

        if (currentScrollY <= 10) {

            navbar.classList.remove("nav-hidden");

        }


        /* Scrolling down */

        else if (currentScrollY > lastScrollY + 5) {

            navbar.classList.add("nav-hidden");

        }


        /* Scrolling up */

        else if (currentScrollY < lastScrollY - 5) {

            navbar.classList.remove("nav-hidden");

        }


        /* Show navbar 1 second after scrolling stops */

        scrollTimer = setTimeout(function () {

            navbar.classList.remove("nav-hidden");

        }, 1000);


        lastScrollY = currentScrollY;

    }, { passive: true });

});
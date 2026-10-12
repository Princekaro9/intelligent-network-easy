// =========================================================
// INPA
// Intelligent Network Packet Analyzer
// Gestion du démarrage de l'application
// =========================================================


document.addEventListener(
    "DOMContentLoaded",
    () => {

        // -------------------------------------------------
        // Récupération du splash screen
        // -------------------------------------------------

        const splashScreen =
            document.getElementById(
                "splash-screen"
            );


        // -------------------------------------------------
        // Vérification
        // -------------------------------------------------

        if (!splashScreen) {

            console.warn(
                "INPA : écran de démarrage introuvable."
            );

            return;

        }


        // -------------------------------------------------
        // Durée du splash
        //
        // 1800 ms = 1,8 seconde
        // -------------------------------------------------

        const SPLASH_DURATION = 1800;


        // -------------------------------------------------
        // Attendre puis commencer la disparition
        // -------------------------------------------------

        setTimeout(
            () => {

                splashScreen.classList.add(
                    "hidden"
                );


                // -------------------------------------------------
                // Supprimer complètement le splash après
                // la transition CSS
                // -------------------------------------------------

                setTimeout(
                    () => {

                        splashScreen.remove();

                    },
                    850
                );

            },
            SPLASH_DURATION
        );

    }
);
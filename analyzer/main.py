"""Boucle principale : detection -> explication IA -> alerting."""

import time
import logging

from config import Config
from detector import run_detection_cycle
from ai_explainer import explain_event
from alerting import dispatch_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("log-analyzer")


def main() -> None:
    logger.info("Demarrage de l'analyseur (intervalle: %ss)", Config.SCAN_INTERVAL)

    while True:
        try:
            results = run_detection_cycle()
            nb_errors = len(results["errors"])
            nb_suspects = len(results["ssh_bruteforce"])
            logger.info(
                "Cycle termine: %d erreur(s), %d IP suspecte(s)", nb_errors, nb_suspects
            )

            for error_event in results["errors"]:
                explanation = explain_event(error_event)
                logger.info("Evenement explique: %s", explanation)
                dispatch_alert(explanation)

            for suspect in results["ssh_bruteforce"]:
                explanation = explain_event(suspect)
                logger.info("Activite suspecte expliquee: %s", explanation)
                dispatch_alert(explanation)

        except Exception:
            logger.exception("Erreur pendant le cycle de detection")

        time.sleep(Config.SCAN_INTERVAL)


if __name__ == "__main__":
    main()

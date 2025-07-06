import time
import random

def run_adaptation(adaptation_decision):
    niveaux = [
        ("normal", "Tout va bien.", []),
        ("alerte", "Attention ! Fatigue détectée.", ["Faites une pause"]),
        ("restriction", "Action sensible, confirmation requise.", ["Confirmez avant d'agir"]),
        ("blocage", "Surcharge critique, accès bloqué.", ["Appelez le superviseur"]),
    ]
    while True:
        niveau, msg, suggestions = random.choice(niveaux)
        adaptation_decision["niveau"] = niveau
        adaptation_decision["message"] = msg
        adaptation_decision["suggestions"] = suggestions
        time.sleep(3)
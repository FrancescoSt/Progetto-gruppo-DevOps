"""
gestione_eventi.py
==================
Programma per la gestione di eventi musicali (concerti, workshop, DJ set),
prenotazioni, partecipanti e disponibilità dei posti.
Interfaccia da terminale, dati salvati in un file JSON locale
("eventi_musicali.json"), creato automaticamente al primo avvio.

Uso:
    python gestione_eventi.py                 avvia il programma (menu)
    python gestione_eventi.py --dati-esempio  ricrea il file dei dati con dati dimostrativi
    python gestione_eventi.py --test          esegue i test automatici

Il file è diviso in sezioni:
    1. ARCHIVIO      lettura e salvataggio dei dati nel file JSON
    2. UTENTI        registrazione, login, password protette e ruoli
    3. EVENTI        creazione, posti disponibili, annullamento e notifiche
    4. PRENOTAZIONI  prenotazioni, approvazione workshop e pagamenti
    5. INTERFACCIA   menu testuali (diversi per ogni ruolo)
    6. DATI DI ESEMPIO
    7. TEST AUTOMATICI
    8. AVVIO
"""

import getpass
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import time
import unittest
from datetime import datetime


# ===========================================================================
# 1. ARCHIVIO: lettura e salvataggio dei dati nel file JSON
# ===========================================================================
#
# Tutti i dati stanno in un unico file JSON con questa struttura:
#
#   {
#     "ultimo_id":    {"utenti": 4, "eventi": 3, "prenotazioni": 5, "notifiche": 0},
#     "utenti":       [ {"id": 1, "username": "admin", ...}, ... ],
#     "eventi":       [ {"id": 1, "nome": "...", "tipo": "concerto", ...}, ... ],
#     "prenotazioni": [ {"id": 1, "utente_id": 2, "evento_id": 1, "posti": [5, 6], ...}, ... ],
#     "notifiche":    [ {"id": 1, "utente_id": 2, "evento_id": 1, "messaggio": "..."}, ... ]
#   }
#
# "ultimo_id" serve a dare a ogni nuovo elemento un numero identificativo
# (id) mai usato prima, come farebbe un database.

# Percorso del file dei dati (stessa cartella di questo programma)
PERCORSO_DATI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eventi_musicali.json")
ELENCHI = ("utenti", "eventi", "prenotazioni", "notifiche")


class ErroreGestione(Exception):
    """
    Errore "previsto" causato da un'operazione non valida
    (es. posto già occupato, capienza superata, permessi insufficienti).
    Il messaggio è già scritto in modo comprensibile per l'utente.
    """


class Archivio:
    """
    Tiene in memoria tutti i dati del programma e li salva nel file JSON.
    Con percorso=None i dati restano solo in memoria (usato nei test).
    """

    def __init__(self, percorso=PERCORSO_DATI):
        self.percorso = percorso
        self.dati = {"ultimo_id": {nome: 0 for nome in ELENCHI}}
        for nome in ELENCHI:
            self.dati[nome] = []
        if percorso is not None and os.path.exists(percorso):
            self.carica()

    def carica(self):
        """Legge il file JSON. Se il file è rovinato si ferma, così non viene sovrascritto."""
        try:
            with open(self.percorso, encoding="utf-8") as file:
                dati = json.load(file)
        except (OSError, json.JSONDecodeError) as errore:
            raise ErroreGestione(f"Impossibile leggere il file dei dati '{self.percorso}': {errore}")
        if (not isinstance(dati, dict) or "ultimo_id" not in dati
                or any(not isinstance(dati.get(nome), list) for nome in ELENCHI)):
            raise ErroreGestione(f"Il file '{self.percorso}' non ha il formato previsto.")
        self.dati = dati

    def salva(self):
        """
        Scrive tutti i dati nel file JSON.
        Prima scrive un file temporaneo e poi lo rinomina: così, se il programma
        si interrompe a metà del salvataggio, il file precedente resta integro.
        """
        if self.percorso is None:
            return
        temporaneo = self.percorso + ".tmp"
        try:
            with open(temporaneo, "w", encoding="utf-8") as file:
                json.dump(self.dati, file, indent=2, ensure_ascii=False)
            os.replace(temporaneo, self.percorso)
        except OSError as errore:
            raise ErroreGestione(f"Impossibile salvare i dati nel file '{self.percorso}': {errore}")

    def elenco(self, nome):
        """Restituisce la lista di un tipo di dati (es. elenco('eventi'))."""
        return self.dati[nome]

    def trova(self, nome, id_cercato):
        """Restituisce l'elemento con l'id indicato, oppure None se non esiste."""
        for elemento in self.dati[nome]:
            if elemento["id"] == id_cercato:
                return elemento
        return None

    def inserisci(self, nome, elemento):
        """Aggiunge un elemento assegnandogli un nuovo id e lo restituisce (non salva su file)."""
        self.dati["ultimo_id"][nome] += 1
        elemento = {"id": self.dati["ultimo_id"][nome], **elemento}
        self.dati[nome].append(elemento)
        return elemento


def apri_archivio(percorso=PERCORSO_DATI):
    """Apre il file dei dati (se non esiste, si parte da un archivio vuoto)."""
    return Archivio(percorso)


# ===========================================================================
# 2. UTENTI: registrazione, login, password protette e ruoli
# ===========================================================================

RUOLI = ("organizzatore", "collaboratore", "partecipante")
ITERAZIONI_HASH = 100_000   # più iterazioni = più difficile indovinare la password

# Account organizzatore creato automaticamente al primo avvio
ORGANIZZATORE_PREDEFINITO = {
    "username": "admin",
    "password": "admin123",
    "nome": "Organizzatore",
    "email": "organizzatore@eventi.local",
}


# ---------------------------------------------------------------------------
# Password
# ---------------------------------------------------------------------------

def calcola_hash_password(password, salt=None):
    """Restituisce (hash, salt) in esadecimale. Se il salt non è dato, ne crea uno casuale."""
    if salt is None:
        salt = os.urandom(16).hex()
    hash_bytes = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                     bytes.fromhex(salt), ITERAZIONI_HASH)
    return hash_bytes.hex(), salt


def verifica_password(password, hash_salvato, salt):
    """Controlla se la password inserita corrisponde all'hash salvato."""
    hash_calcolato, _ = calcola_hash_password(password, salt)
    # compare_digest confronta in tempo costante (buona pratica di sicurezza)
    return hmac.compare_digest(hash_calcolato, hash_salvato)


# ---------------------------------------------------------------------------
# Controlli sui dati inseriti
# Ogni funzione restituisce il valore "ripulito" oppure solleva ErroreGestione.
# Sono usate sia da registra_utente() sia dal menu, che così può segnalare
# un errore subito dopo il campo sbagliato.
# ---------------------------------------------------------------------------

def normalizza_username(username):
    """Gli username non distinguono maiuscole e minuscole: 'Anna' e 'anna' sono lo stesso utente."""
    return (username or "").strip().lower()


def cerca_utente(db, username):
    """Restituisce l'utente con quello username, oppure None."""
    username = normalizza_username(username)
    for utente in db.elenco("utenti"):
        if utente["username"] == username:
            return utente
    return None


def controlla_username(db, username):
    username = normalizza_username(username)
    if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
        raise ErroreGestione("Lo username deve avere da 3 a 20 caratteri (lettere senza accenti, numeri o _).")
    if cerca_utente(db, username) is not None:
        raise ErroreGestione(f"Lo username '{username}' è già in uso.")
    return username


def controlla_nome(nome):
    nome = " ".join((nome or "").split())   # toglie gli spazi in eccesso
    if not 2 <= len(nome) <= 50:
        raise ErroreGestione("Il nome deve avere da 2 a 50 caratteri.")
    if not any(c.isalpha() for c in nome):
        raise ErroreGestione("Il nome deve contenere almeno una lettera.")
    return nome


def controlla_email(db, email):
    email = (email or "").strip().lower()
    if len(email) > 100 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ErroreGestione("Indirizzo email non valido (esempio: nome@dominio.it).")
    if any(utente["email"] == email for utente in db.elenco("utenti")):
        raise ErroreGestione("Esiste già un account registrato con questa email.")
    return email


def valida_password(password, username=""):
    """Regole minime: almeno 6 caratteri, almeno una lettera e un numero, diversa dallo username."""
    password = password or ""
    if len(password) < 6:
        raise ErroreGestione("La password deve contenere almeno 6 caratteri.")
    if len(password) > 100:
        raise ErroreGestione("La password non può superare i 100 caratteri.")
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise ErroreGestione("La password deve contenere almeno una lettera e un numero.")
    if username and password.lower() == normalizza_username(username):
        raise ErroreGestione("La password non può essere uguale allo username.")


# ---------------------------------------------------------------------------
# Registrazione e login
# ---------------------------------------------------------------------------

def registra_utente(db, username, nome, email, password, ruolo="partecipante"):
    """
    Registra un nuovo utente e ne restituisce l'id.
    Dal menu pubblico si possono registrare solo partecipanti;
    i collaboratori vengono creati dall'organizzatore (vedi crea_collaboratore).
    """
    if ruolo not in RUOLI:
        raise ErroreGestione("Ruolo non valido.")
    username = controlla_username(db, username)
    nome = controlla_nome(nome)
    email = controlla_email(db, email)
    valida_password(password, username)

    hash_pw, salt = calcola_hash_password(password)
    utente = db.inserisci("utenti", {
        "username": username, "nome": nome, "email": email,
        "password_hash": hash_pw,   # hash della password, MAI la password in chiaro
        "salt": salt,               # valore casuale usato per l'hash
        "ruolo": ruolo,
    })
    db.salva()
    return utente["id"]


# Hash "finto" usato quando lo username non esiste: così il login impiega
# lo stesso tempo e non si può capire quali username sono registrati.
_SALT_FINTO = os.urandom(16).hex()
_HASH_FINTO, _ = calcola_hash_password("password-inesistente", _SALT_FINTO)


def login(db, username, password):
    """
    Verifica le credenziali. Restituisce un dizionario con i dati dell'utente
    (id, username, nome, ruolo, password_predefinita) oppure solleva ErroreGestione.
    """
    username = normalizza_username(username)
    utente = cerca_utente(db, username)
    if utente is None:
        verifica_password(password or "", _HASH_FINTO, _SALT_FINTO)  # stesso tempo di calcolo
        raise ErroreGestione("Username o password errati.")
    # Stesso messaggio per username o password errati: non si rivela quale dei due è sbagliato
    if not verifica_password(password or "", utente["password_hash"], utente["salt"]):
        raise ErroreGestione("Username o password errati.")
    d = ORGANIZZATORE_PREDEFINITO
    return {"id": utente["id"], "username": utente["username"],
            "nome": utente["nome"], "ruolo": utente["ruolo"],
            "password_predefinita": username == d["username"] and password == d["password"]}


def cambia_password(db, utente, vecchia_password, nuova_password):
    """Permette all'utente autenticato di cambiare la propria password."""
    registrato = db.trova("utenti", utente["id"])
    if not verifica_password(vecchia_password or "", registrato["password_hash"], registrato["salt"]):
        raise ErroreGestione("La password attuale non è corretta.")
    if nuova_password == vecchia_password:
        raise ErroreGestione("La nuova password deve essere diversa da quella attuale.")
    valida_password(nuova_password, registrato["username"])
    registrato["password_hash"], registrato["salt"] = calcola_hash_password(nuova_password)
    db.salva()
    utente["password_predefinita"] = False


def crea_collaboratore(db, utente, username, nome, email, password):
    """Solo l'organizzatore può creare account di tipo collaboratore."""
    richiedi_ruolo(utente, "organizzatore")
    return registra_utente(db, username, nome, email, password, ruolo="collaboratore")


def crea_organizzatore_predefinito(db):
    """
    Al primo avvio non esiste nessun organizzatore: ne viene creato uno
    predefinito, così è possibile accedere e creare gli eventi.
    Restituisce True se l'account è stato creato ora.
    """
    if any(u["ruolo"] == "organizzatore" for u in db.elenco("utenti")):
        return False
    d = ORGANIZZATORE_PREDEFINITO
    registra_utente(db, d["username"], d["nome"], d["email"], d["password"], "organizzatore")
    return True


# ---------------------------------------------------------------------------
# Controllo dei permessi
# ---------------------------------------------------------------------------

def richiedi_ruolo(utente, *ruoli_ammessi):
    """Solleva un errore se l'utente non ha uno dei ruoli ammessi."""
    if utente is None or utente["ruolo"] not in ruoli_ammessi:
        raise ErroreGestione("Operazione non consentita per il tuo ruolo.")


# ===========================================================================
# 3. EVENTI: creazione, posti disponibili, annullamento e notifiche
# ===========================================================================
#
# Tipologie di evento:
# - concerto : posti numerati (da 1 a capienza), a pagamento o gratuito
# - workshop : capienza massima, prenotazioni da approvare
# - dj_set   : sempre gratuito, prenotazioni confermate automaticamente

TIPI_EVENTO = {"concerto": "Concerto", "workshop": "Workshop", "dj_set": "DJ set"}
FORMATO_DATI = "%Y-%m-%d %H:%M"        # come la data viene salvata nel file
FORMATO_UTENTE = "%d/%m/%Y %H:%M"      # come la data viene scritta/letta dall'utente
CAPIENZA_MASSIMA = 10_000


# ---------------------------------------------------------------------------
# Date
# ---------------------------------------------------------------------------

def converti_data(testo):
    """Converte 'GG/MM/AAAA HH:MM' nel formato del file. Solleva errore se non valida."""
    try:
        data = datetime.strptime((testo or "").strip(), FORMATO_UTENTE)
    except ValueError:
        raise ErroreGestione("Data non valida. Usa il formato GG/MM/AAAA HH:MM (es. 15/03/2027 21:00).")
    return data.strftime(FORMATO_DATI)


def formatta_data(data_salvata):
    """Converte la data salvata nel formato leggibile dall'utente."""
    return datetime.strptime(data_salvata, FORMATO_DATI).strftime(FORMATO_UTENTE)


def evento_passato(evento):
    return datetime.strptime(evento["data_ora"], FORMATO_DATI) < datetime.now()


# ---------------------------------------------------------------------------
# Creazione e lettura degli eventi
# ---------------------------------------------------------------------------

def crea_evento(db, utente, nome, tipo, data_ora, luogo, capienza, prezzo=0.0, descrizione=""):
    """
    Crea un nuovo evento (solo organizzatore) e ne restituisce l'id.
    data_ora deve essere nel formato 'GG/MM/AAAA HH:MM'.
    Per i concerti i posti sono numerati da 1 a capienza.
    """
    richiedi_ruolo(utente, "organizzatore")

    # --- controlli sui dati ---
    nome = (nome or "").strip()
    luogo = (luogo or "").strip()
    if not nome:
        raise ErroreGestione("Il nome dell'evento non può essere vuoto.")
    if not luogo:
        raise ErroreGestione("Il luogo non può essere vuoto.")
    if tipo not in TIPI_EVENTO:
        raise ErroreGestione("Tipo di evento non valido (concerto, workshop o dj_set).")
    data_salvata = converti_data(data_ora)
    if datetime.strptime(data_salvata, FORMATO_DATI) < datetime.now():
        raise ErroreGestione("Non è possibile creare un evento con una data già passata.")
    if not isinstance(capienza, int) or not 1 <= capienza <= CAPIENZA_MASSIMA:
        raise ErroreGestione(f"La capienza deve essere un numero intero tra 1 e {CAPIENZA_MASSIMA}.")
    try:
        prezzo = round(float(prezzo), 2)
    except (TypeError, ValueError):
        raise ErroreGestione("Prezzo non valido.")
    if prezzo < 0:
        raise ErroreGestione("Il prezzo non può essere negativo.")
    if tipo == "dj_set":
        prezzo = 0.0  # regola: il DJ set è sempre gratuito

    evento = db.inserisci("eventi", {
        "nome": nome, "tipo": tipo, "data_ora": data_salvata, "luogo": luogo,
        "descrizione": (descrizione or "").strip(), "capienza": capienza,
        "prezzo": prezzo, "stato": "attivo", "creato_da": utente["id"],
    })
    db.salva()
    return evento["id"]


def ottieni_evento(db, evento_id):
    """Restituisce l'evento oppure solleva un errore se non esiste."""
    evento = db.trova("eventi", evento_id)
    if evento is None:
        raise ErroreGestione(f"Nessun evento con id {evento_id}.")
    return evento


def prenotazioni_confermate(db, evento_id):
    return [p for p in db.elenco("prenotazioni")
            if p["evento_id"] == evento_id and p["stato"] == "confermata"]


def posti_occupati(db, evento_id):
    """Numero di posti occupati: contano solo le prenotazioni confermate."""
    return sum(p["num_posti"] for p in prenotazioni_confermate(db, evento_id))


def posti_liberi_concerto(db, evento_id):
    """Elenco dei numeri di posto ancora liberi di un concerto."""
    evento = ottieni_evento(db, evento_id)
    occupati = {n for p in prenotazioni_confermate(db, evento_id) for n in p["posti"]}
    return [n for n in range(1, evento["capienza"] + 1) if n not in occupati]


def posti_disponibili(db, evento_id):
    """Numero di posti ancora prenotabili per un evento."""
    evento = ottieni_evento(db, evento_id)
    return evento["capienza"] - posti_occupati(db, evento_id)


def elenca_eventi(db, includi_annullati=False):
    """Restituisce gli eventi ordinati per data, con i posti disponibili calcolati."""
    risultato = []
    for evento in sorted(db.elenco("eventi"), key=lambda e: e["data_ora"]):
        if evento["stato"] == "annullato" and not includi_annullati:
            continue
        dati = dict(evento)   # copia, per non modificare i dati salvati
        dati["disponibili"] = posti_disponibili(db, evento["id"])
        risultato.append(dati)
    return risultato


def formatta_intervalli(numeri):
    """Rende compatto un elenco di posti: [1,2,3,7,8] -> '1-3, 7-8'."""
    if not numeri:
        return "nessuno"
    parti, inizio, prec = [], numeri[0], numeri[0]
    for n in numeri[1:] + [None]:
        if n is not None and n == prec + 1:
            prec = n
            continue
        parti.append(str(inizio) if inizio == prec else f"{inizio}-{prec}")
        if n is not None:
            inizio = prec = n
    return ", ".join(parti)


# ---------------------------------------------------------------------------
# Annullamento evento e notifiche simulate
# ---------------------------------------------------------------------------

def annulla_evento(db, utente, evento_id):
    """
    Annulla un evento (solo organizzatore):
    - l'evento passa allo stato 'annullato';
    - tutte le prenotazioni attive vengono annullate (i posti si liberano);
    - i pagamenti già effettuati diventano 'da_rimborsare';
    - ogni partecipante interessato riceve una notifica simulata.
    Restituisce l'elenco delle notifiche inviate (username, email, messaggio).
    """
    richiedi_ruolo(utente, "organizzatore")
    evento = ottieni_evento(db, evento_id)
    if evento["stato"] == "annullato":
        raise ErroreGestione("L'evento è già stato annullato.")

    messaggio = (f"L'evento '{evento['nome']}' del {formatta_data(evento['data_ora'])} "
                 f"presso {evento['luogo']} è stato annullato. "
                 f"Le tue prenotazioni sono state annullate; eventuali pagamenti saranno rimborsati.")
    adesso = datetime.now().strftime(FORMATO_DATI)

    evento["stato"] = "annullato"
    interessati = []   # id dei partecipanti con almeno una prenotazione attiva
    for p in db.elenco("prenotazioni"):
        if p["evento_id"] == evento_id and p["stato"] in ("in_attesa", "confermata"):
            p["stato"] = "annullata"
            if p["stato_pagamento"] == "pagato":
                p["stato_pagamento"] = "da_rimborsare"
            if p["utente_id"] not in interessati:
                interessati.append(p["utente_id"])

    inviate = []
    for utente_id in interessati:   # una sola notifica per partecipante
        destinatario = db.trova("utenti", utente_id)
        db.inserisci("notifiche", {"utente_id": utente_id, "evento_id": evento_id,
                                   "messaggio": messaggio, "data_invio": adesso})
        inviate.append((destinatario["username"], destinatario["email"], messaggio))
    db.salva()
    return inviate


def notifiche_utente(db, utente):
    """Notifiche ricevute dall'utente autenticato (dalla più recente)."""
    return [n for n in reversed(db.elenco("notifiche")) if n["utente_id"] == utente["id"]]


# ===========================================================================
# 4. PRENOTAZIONI: prenotazioni, workshop e pagamenti
# ===========================================================================
#
# Stati di una prenotazione:
#     in_attesa  -> solo workshop, in attesa dell'approvazione dell'organizzatore
#     confermata -> posti assegnati
#     rifiutata  -> richiesta di workshop rifiutata
#     annullata  -> annullata dall'utente, dallo staff o per annullamento dell'evento
#
# Stati del pagamento:
#     gratuito, non_pagato, pagato, da_rimborsare, rimborsato
#
# Un posto è occupato solo se appartiene a una prenotazione "confermata":
# quando una prenotazione viene annullata, i suoi posti tornano liberi da soli.

STATI_PAGAMENTO_MODIFICABILI = ("non_pagato", "pagato", "da_rimborsare", "rimborsato")
STAFF = ("organizzatore", "collaboratore")


# ---------------------------------------------------------------------------
# Funzioni di supporto
# ---------------------------------------------------------------------------

def _controlla_evento_prenotabile(db, evento_id):
    """Verifica che l'evento esista, sia attivo e non sia già passato."""
    evento = ottieni_evento(db, evento_id)
    if evento["stato"] != "attivo":
        raise ErroreGestione("L'evento è stato annullato: non è possibile prenotare.")
    if evento_passato(evento):
        raise ErroreGestione("L'evento si è già svolto: non è possibile prenotare.")
    return evento


def _inserisci_prenotazione(db, utente_id, evento_id, num_posti, stato, importo, posti=None):
    prenotazione = db.inserisci("prenotazioni", {
        "utente_id": utente_id, "evento_id": evento_id, "num_posti": num_posti,
        "posti": posti or [],          # numeri dei posti (solo concerti)
        "stato": stato, "importo": importo,
        "stato_pagamento": "gratuito" if importo == 0 else "non_pagato",
        "data_prenotazione": datetime.now().strftime(FORMATO_DATI),
    })
    db.salva()
    return prenotazione["id"]


def ottieni_prenotazione(db, prenotazione_id):
    p = db.trova("prenotazioni", prenotazione_id)
    if p is None:
        raise ErroreGestione(f"Nessuna prenotazione con id {prenotazione_id}.")
    return p


def numeri_posti_prenotazione(db, prenotazione_id):
    """Numeri dei posti (concerti) di una prenotazione."""
    return ottieni_prenotazione(db, prenotazione_id)["posti"]


# ---------------------------------------------------------------------------
# Prenotazione
# ---------------------------------------------------------------------------

def prenota_concerto(db, utente, evento_id, numeri_posti):
    """
    Prenota uno o più posti numerati di un concerto.
    Prima controlla TUTTI i posti richiesti: se anche uno solo non è
    disponibile, non viene prenotato nulla. Restituisce l'id della prenotazione.
    """
    richiedi_ruolo(utente, "partecipante")
    evento = _controlla_evento_prenotabile(db, evento_id)
    if evento["tipo"] != "concerto":
        raise ErroreGestione("Questo evento non ha posti numerati.")

    numeri = sorted(set(numeri_posti or []))
    if not numeri:
        raise ErroreGestione("Indica almeno un posto da prenotare.")
    for n in numeri:
        if not 1 <= n <= evento["capienza"]:
            raise ErroreGestione(f"Il posto {n} non esiste (posti da 1 a {evento['capienza']}).")
    liberi = set(posti_liberi_concerto(db, evento_id))
    occupati = [n for n in numeri if n not in liberi]
    if occupati:
        elenco = ", ".join(map(str, occupati))
        raise ErroreGestione(f"Posti già occupati: {elenco}. Nessun posto è stato prenotato.")

    importo = round(evento["prezzo"] * len(numeri), 2)
    return _inserisci_prenotazione(db, utente["id"], evento_id, len(numeri), "confermata", importo, numeri)


def prenota_posti(db, utente, evento_id, num_posti):
    """
    Prenota un certo numero di posti per un workshop o un DJ set.
    - Workshop: la prenotazione resta 'in_attesa' finché l'organizzatore non la approva.
    - DJ set:   la prenotazione è confermata subito se ci sono posti.
    Restituisce l'id della prenotazione.
    """
    richiedi_ruolo(utente, "partecipante")
    evento = _controlla_evento_prenotabile(db, evento_id)
    if evento["tipo"] == "concerto":
        raise ErroreGestione("Per i concerti bisogna scegliere i posti numerati.")
    if not isinstance(num_posti, int) or num_posti < 1:
        raise ErroreGestione("Il numero di posti deve essere almeno 1.")

    liberi = posti_disponibili(db, evento_id)
    if num_posti > liberi:
        raise ErroreGestione(f"Posti insufficienti: richiesti {num_posti}, disponibili {liberi}.")

    stato = "in_attesa" if evento["tipo"] == "workshop" else "confermata"
    importo = round(evento["prezzo"] * num_posti, 2)
    return _inserisci_prenotazione(db, utente["id"], evento_id, num_posti, stato, importo)


# ---------------------------------------------------------------------------
# Consultazione
# ---------------------------------------------------------------------------

def _con_dettagli(db, p):
    """Copia della prenotazione con i dati dell'evento e dello username (per la stampa)."""
    evento = db.trova("eventi", p["evento_id"])
    utente = db.trova("utenti", p["utente_id"])
    return {**p, "nome_evento": evento["nome"], "tipo_evento": evento["tipo"],
            "data_ora": evento["data_ora"], "stato_evento": evento["stato"],
            "username": utente["username"]}


def elenca_prenotazioni_utente(db, utente):
    """Prenotazioni dell'utente autenticato (un partecipante vede SOLO le proprie)."""
    return [_con_dettagli(db, p) for p in db.elenco("prenotazioni") if p["utente_id"] == utente["id"]]


def elenca_tutte_prenotazioni(db, utente, evento_id=None):
    """Tutte le prenotazioni (eventualmente di un solo evento): solo organizzatore e collaboratore."""
    richiedi_ruolo(utente, *STAFF)
    return [_con_dettagli(db, p) for p in db.elenco("prenotazioni")
            if evento_id is None or p["evento_id"] == evento_id]


# ---------------------------------------------------------------------------
# Annullamento di una prenotazione
# ---------------------------------------------------------------------------

def annulla_prenotazione(db, utente, prenotazione_id):
    """
    Annulla una prenotazione in attesa o confermata (i posti tornano liberi).
    Un partecipante può annullare solo le proprie prenotazioni;
    organizzatore e collaboratore possono annullare qualsiasi prenotazione.
    Se era già stata pagata, il pagamento diventa 'da_rimborsare'.
    """
    richiedi_ruolo(utente, "partecipante", *STAFF)
    p = ottieni_prenotazione(db, prenotazione_id)

    if utente["ruolo"] == "partecipante" and p["utente_id"] != utente["id"]:
        # Stesso messaggio di "non esiste": non si rivelano le prenotazioni altrui
        raise ErroreGestione(f"Nessuna prenotazione con id {prenotazione_id}.")
    if p["stato"] not in ("in_attesa", "confermata"):
        raise ErroreGestione(f"La prenotazione è già nello stato '{p['stato']}' e non può essere annullata.")

    p["stato"] = "annullata"
    if p["stato_pagamento"] == "pagato":
        p["stato_pagamento"] = "da_rimborsare"
    db.salva()


# ---------------------------------------------------------------------------
# Approvazione dei workshop (solo organizzatore)
# ---------------------------------------------------------------------------

def richieste_workshop_in_attesa(db, utente):
    richiedi_ruolo(utente, "organizzatore")
    return [_con_dettagli(db, p) for p in db.elenco("prenotazioni")
            if p["stato"] == "in_attesa" and db.trova("eventi", p["evento_id"])["stato"] == "attivo"]


def _richiesta_workshop(db, utente, prenotazione_id):
    richiedi_ruolo(utente, "organizzatore")
    p = ottieni_prenotazione(db, prenotazione_id)
    evento = ottieni_evento(db, p["evento_id"])
    if evento["tipo"] != "workshop":
        raise ErroreGestione("Solo le prenotazioni dei workshop richiedono approvazione.")
    if p["stato"] != "in_attesa":
        raise ErroreGestione(f"La richiesta non è in attesa (stato attuale: '{p['stato']}').")
    return p, evento


def approva_prenotazione(db, utente, prenotazione_id):
    """Approva una richiesta di workshop solo se c'è ancora capienza sufficiente."""
    p, evento = _richiesta_workshop(db, utente, prenotazione_id)
    liberi = posti_disponibili(db, evento["id"])
    if p["num_posti"] > liberi:
        raise ErroreGestione(
            f"Impossibile approvare: la richiesta è di {p['num_posti']} posti "
            f"ma ne restano solo {liberi}. Puoi rifiutarla.")
    p["stato"] = "confermata"
    db.salva()


def rifiuta_prenotazione(db, utente, prenotazione_id):
    """Rifiuta una richiesta di workshop."""
    p, _ = _richiesta_workshop(db, utente, prenotazione_id)
    p["stato"] = "rifiutata"
    db.salva()


# ---------------------------------------------------------------------------
# Pagamenti (organizzatore e collaboratore)
# ---------------------------------------------------------------------------

def aggiorna_pagamento(db, utente, prenotazione_id, nuovo_stato):
    """Aggiorna lo stato del pagamento di una prenotazione (registrazione manuale, non online)."""
    richiedi_ruolo(utente, *STAFF)
    if nuovo_stato not in STATI_PAGAMENTO_MODIFICABILI:
        raise ErroreGestione("Stato di pagamento non valido.")
    p = ottieni_prenotazione(db, prenotazione_id)
    if p["stato_pagamento"] == "gratuito":
        raise ErroreGestione("La prenotazione è gratuita: non c'è nessun pagamento da gestire.")
    if p["stato"] in ("annullata", "rifiutata") and nuovo_stato == "pagato":
        raise ErroreGestione("Non si può segnare come pagata una prenotazione annullata o rifiutata.")
    p["stato_pagamento"] = nuovo_stato
    db.salva()


# ===========================================================================
# 5. INTERFACCIA: menu testuali
# ===========================================================================

ETICHETTE_STATO = {
    "in_attesa": "in attesa", "confermata": "confermata",
    "rifiutata": "rifiutata", "annullata": "annullata",
    "gratuito": "gratuito", "non_pagato": "non pagato", "pagato": "pagato",
    "da_rimborsare": "da rimborsare", "rimborsato": "rimborsato",
}


# ---------------------------------------------------------------------------
# Funzioni di input con controllo dei dati
# ---------------------------------------------------------------------------

def chiedi_testo(domanda, obbligatorio=True):
    while True:
        valore = input(domanda).strip()
        if valore or not obbligatorio:
            return valore
        print("  ! Il campo non può essere vuoto.")


def chiedi_intero(domanda, minimo=None, massimo=None):
    """Chiede un numero intero finché l'utente non ne inserisce uno valido."""
    while True:
        valore = input(domanda).strip()
        try:
            numero = int(valore)
        except ValueError:
            print("  ! Inserisci un numero intero.")
            continue
        if minimo is not None and numero < minimo:
            print(f"  ! Il numero deve essere almeno {minimo}.")
            continue
        if massimo is not None and numero > massimo:
            print(f"  ! Il numero non può superare {massimo}.")
            continue
        return numero


def chiedi_decimale(domanda):
    while True:
        valore = input(domanda).strip().replace(",", ".")
        try:
            numero = float(valore)
            if numero >= 0:
                return numero
        except ValueError:
            pass
        print("  ! Inserisci un numero maggiore o uguale a 0 (es. 25 oppure 12.50).")


def chiedi_data(domanda):
    """Chiede una data futura nel formato GG/MM/AAAA HH:MM finché non è valida."""
    while True:
        testo = chiedi_testo(domanda)
        try:
            data_salvata = converti_data(testo)
        except ErroreGestione as errore:
            print(f"  ! {errore}")
            continue
        if datetime.strptime(data_salvata, FORMATO_DATI) < datetime.now():
            print("  ! La data è già passata: inserisci una data futura.")
            continue
        return testo


def chiedi_password(domanda="Password: "):
    """Nasconde la password se il programma gira in un terminale vero."""
    if sys.stdin.isatty():
        return getpass.getpass(domanda)
    return input(domanda)


def chiedi_lista_posti(domanda):
    """Legge un elenco di posti come '3, 4, 10-12' e restituisce [3, 4, 10, 11, 12]."""
    while True:
        testo = input(domanda).replace(" ", "")
        try:
            numeri = []
            for parte in testo.split(","):
                if "-" in parte:
                    inizio, fine = (int(x) for x in parte.split("-"))
                    if fine < inizio or fine - inizio > 500:
                        raise ValueError
                    numeri.extend(range(inizio, fine + 1))
                else:
                    numeri.append(int(parte))
            return numeri
        except ValueError:
            print("  ! Formato non valido. Esempi: 5   oppure   3,4,7   oppure   10-12")


def conferma(domanda):
    return input(domanda + " (s/n): ").strip().lower() in ("s", "si", "sì")


# ---------------------------------------------------------------------------
# Stampa di eventi e prenotazioni
# ---------------------------------------------------------------------------

def stampa_eventi(db, includi_annullati=False):
    elenco = elenca_eventi(db, includi_annullati)
    if not elenco:
        print("\nNessun evento disponibile.")
        return
    print(f"\n{'ID':>3}  {'Tipo':<9} {'Data':<16}  {'Nome':<28} {'Prezzo':>8} {'Posti liberi':>13}")
    print("-" * 84)
    for e in elenco:
        prezzo = "gratis" if e["prezzo"] == 0 else f"€{e['prezzo']:.2f}"
        posti = f"{e['disponibili']}/{e['capienza']}"
        if e["stato"] == "annullato":
            posti = "ANNULLATO"
        print(f"{e['id']:>3}  {TIPI_EVENTO[e['tipo']]:<9} {formatta_data(e['data_ora']):<16}  "
              f"{e['nome'][:28]:<28} {prezzo:>8} {posti:>13}")


def stampa_prenotazioni(db, elenco, mostra_utente=False):
    if not elenco:
        print("\nNessuna prenotazione trovata.")
        return
    print()
    for p in elenco:
        dettaglio = f"{p['num_posti']} posto/i"
        if p["tipo_evento"] == "concerto":
            numeri = numeri_posti_prenotazione(db, p["id"])
            if numeri:
                dettaglio = "posti " + formatta_intervalli(numeri)
        utente = f" | utente: {p['username']}" if mostra_utente else ""
        importo = "" if p["importo"] == 0 else f" | €{p['importo']:.2f}"
        print(f"#{p['id']:<4} {p['nome_evento'][:30]:<30} ({formatta_data(p['data_ora'])}) "
              f"| {dettaglio} | {ETICHETTE_STATO[p['stato']]} "
              f"| pagamento: {ETICHETTE_STATO[p['stato_pagamento']]}{importo}{utente}")


# ---------------------------------------------------------------------------
# Azioni comuni
# ---------------------------------------------------------------------------

def azione_visualizza_eventi(db, utente):
    staff = utente is not None and utente["ruolo"] in STAFF
    stampa_eventi(db, includi_annullati=staff)


def azione_dettagli_evento(db, utente):
    evento = ottieni_evento(db, chiedi_intero("ID dell'evento: "))
    print(f"\n=== {evento['nome']} ===")
    print(f"Tipo:        {TIPI_EVENTO[evento['tipo']]}")
    print(f"Data e ora:  {formatta_data(evento['data_ora'])}")
    print(f"Luogo:       {evento['luogo']}")
    if evento["descrizione"]:
        print(f"Descrizione: {evento['descrizione']}")
    prezzo = "gratuito" if evento["prezzo"] == 0 else f"€{evento['prezzo']:.2f} a posto"
    print(f"Prezzo:      {prezzo}")
    print(f"Stato:       {evento['stato']}")
    print(f"Capienza:    {evento['capienza']} | disponibili: {posti_disponibili(db, evento['id'])}")
    if evento["tipo"] == "concerto" and evento["stato"] == "attivo":
        print(f"Posti liberi: {formatta_intervalli(posti_liberi_concerto(db, evento['id']))}")
    if evento["tipo"] == "workshop":
        print("Nota: le prenotazioni devono essere approvate dall'organizzatore.")
    if utente is not None and utente["ruolo"] in STAFF:
        print("\nPrenotazioni dell'evento:")
        stampa_prenotazioni(db, elenca_tutte_prenotazioni(db, utente, evento["id"]), True)


def azione_cambia_password(db, utente):
    vecchia = chiedi_password("Password attuale: ")
    nuova = chiedi_password("Nuova password (min. 6 caratteri, almeno una lettera e un numero): ")
    if nuova != chiedi_password("Ripeti la nuova password: "):
        print("  ! Le password non coincidono.")
        return
    cambia_password(db, utente, vecchia, nuova)
    print("Password aggiornata.")


# ---------------------------------------------------------------------------
# Azioni del partecipante
# ---------------------------------------------------------------------------

def azione_prenota(db, utente):
    stampa_eventi(db)
    evento = ottieni_evento(db, chiedi_intero("\nID dell'evento da prenotare: "))
    if evento["tipo"] == "concerto":
        liberi = posti_liberi_concerto(db, evento["id"])
        print(f"Posti liberi: {formatta_intervalli(liberi)}")
        numeri = chiedi_lista_posti("Posti da prenotare (es. 5  oppure  3,4  oppure  10-12): ")
        non_liberi = sorted(set(numeri) - set(liberi))
        if non_liberi:
            print(f"  ! Posti non disponibili: {', '.join(map(str, non_liberi))}. Nessun posto prenotato.")
            return
        totale = evento["prezzo"] * len(set(numeri))
        if not conferma(f"Confermi {len(set(numeri))} posto/i per un totale di €{totale:.2f}?"):
            return
        pid = prenota_concerto(db, utente, evento["id"], numeri)
        print(f"Prenotazione #{pid} confermata.")
    else:
        disponibili = posti_disponibili(db, evento["id"])
        print(f"Posti disponibili: {disponibili}")
        num = chiedi_intero("Quanti posti vuoi prenotare? ", 1)
        pid = prenota_posti(db, utente, evento["id"], num)
        if evento["tipo"] == "workshop":
            print(f"Richiesta #{pid} inviata: è in attesa di approvazione dell'organizzatore.")
        else:
            print(f"Prenotazione #{pid} confermata (ingresso gratuito).")


def azione_mie_prenotazioni(db, utente):
    stampa_prenotazioni(db, elenca_prenotazioni_utente(db, utente))


def azione_annulla_prenotazione(db, utente):
    if utente["ruolo"] == "partecipante":
        azione_mie_prenotazioni(db, utente)
    else:
        stampa_prenotazioni(db, elenca_tutte_prenotazioni(db, utente), True)
    pid = chiedi_intero("\nID della prenotazione da annullare (0 = indietro): ", 0)
    if pid == 0 or not conferma(f"Annullare la prenotazione #{pid}?"):
        return
    annulla_prenotazione(db, utente, pid)
    print(f"Prenotazione #{pid} annullata. I posti sono di nuovo disponibili.")


def azione_mie_notifiche(db, utente):
    elenco = notifiche_utente(db, utente)
    if not elenco:
        print("\nNessuna notifica.")
    for n in elenco:
        print(f"\n[{formatta_data(n['data_invio'])}] {n['messaggio']}")


# ---------------------------------------------------------------------------
# Azioni di organizzatore e collaboratore
# ---------------------------------------------------------------------------

def azione_tutte_prenotazioni(db, utente):
    stampa_prenotazioni(db, elenca_tutte_prenotazioni(db, utente), True)


def azione_crea_evento(db, utente):
    print("\nTipo di evento:  1) Concerto   2) Workshop   3) DJ set")
    tipo = ("concerto", "workshop", "dj_set")[chiedi_intero("Scelta: ", 1, 3) - 1]
    nome = chiedi_testo("Nome evento: ")
    data = chiedi_data("Data e ora (GG/MM/AAAA HH:MM): ")
    luogo = chiedi_testo("Luogo: ")
    descrizione = chiedi_testo("Descrizione (facoltativa): ", obbligatorio=False)
    etichetta = "Numero di posti numerati" if tipo == "concerto" else "Capienza massima"
    capienza = chiedi_intero(f"{etichetta}: ", 1, CAPIENZA_MASSIMA)
    prezzo = 0.0 if tipo == "dj_set" else chiedi_decimale("Prezzo a posto in € (0 = gratuito): ")
    eid = crea_evento(db, utente, nome, tipo, data, luogo, capienza, prezzo, descrizione)
    print(f"Evento #{eid} creato.")


def azione_approva_workshop(db, utente):
    richieste = richieste_workshop_in_attesa(db, utente)
    if not richieste:
        print("\nNessuna richiesta in attesa.")
        return
    for r in richieste:
        print(f"#{r['id']:<4} {r['nome_evento']} | utente: {r['username']} | posti richiesti: {r['num_posti']} "
              f"| liberi: {posti_disponibili(db, r['evento_id'])}")
    pid = chiedi_intero("\nID della richiesta (0 = indietro): ", 0)
    if pid == 0:
        return
    scelta = chiedi_intero("1) Approva   2) Rifiuta : ", 1, 2)
    if scelta == 1:
        approva_prenotazione(db, utente, pid)
        print(f"Richiesta #{pid} approvata.")
    else:
        rifiuta_prenotazione(db, utente, pid)
        print(f"Richiesta #{pid} rifiutata.")


def azione_pagamenti(db, utente):
    elenco = [p for p in elenca_tutte_prenotazioni(db, utente)
              if p["stato_pagamento"] != "gratuito"]
    stampa_prenotazioni(db, elenco, True)
    if not elenco:
        return
    pid = chiedi_intero("\nID della prenotazione da aggiornare (0 = indietro): ", 0)
    if pid == 0:
        return
    stati = STATI_PAGAMENTO_MODIFICABILI
    for i, s in enumerate(stati, 1):
        print(f"  {i}) {ETICHETTE_STATO[s]}")
    nuovo = stati[chiedi_intero("Nuovo stato del pagamento: ", 1, len(stati)) - 1]
    aggiorna_pagamento(db, utente, pid, nuovo)
    print(f"Pagamento della prenotazione #{pid} aggiornato a '{ETICHETTE_STATO[nuovo]}'.")


def azione_annulla_evento(db, utente):
    stampa_eventi(db)
    eid = chiedi_intero("\nID dell'evento da annullare (0 = indietro): ", 0)
    if eid == 0:
        return
    evento = ottieni_evento(db, eid)
    if not conferma(f"Annullare definitivamente '{evento['nome']}'?"):
        return
    inviate = annulla_evento(db, utente, eid)
    print(f"Evento '{evento['nome']}' annullato.")
    print(f"Notifiche inviate (simulazione): {len(inviate)}")
    for username, email, messaggio in inviate:
        print(f"  [NOTIFICA -> {username} <{email}>] {messaggio}")


def azione_crea_collaboratore(db, utente):
    print("\n--- Nuovo account collaboratore ---")
    dati = chiedi_dati_account(db)
    if dati is None:
        return
    crea_collaboratore(db, utente, *dati)
    print(f"Collaboratore '{dati[0]}' creato.")


# ---------------------------------------------------------------------------
# Menu per ruolo: elenco di (descrizione, funzione)
# ---------------------------------------------------------------------------

MENU_PER_RUOLO = {
    "partecipante": [
        ("Visualizza eventi", azione_visualizza_eventi),
        ("Dettagli di un evento", azione_dettagli_evento),
        ("Prenota posti", azione_prenota),
        ("Le mie prenotazioni", azione_mie_prenotazioni),
        ("Annulla una mia prenotazione", azione_annulla_prenotazione),
        ("Le mie notifiche", azione_mie_notifiche),
        ("Cambia password", azione_cambia_password),
    ],
    "collaboratore": [
        ("Visualizza eventi", azione_visualizza_eventi),
        ("Dettagli di un evento (con prenotazioni)", azione_dettagli_evento),
        ("Visualizza tutte le prenotazioni", azione_tutte_prenotazioni),
        ("Annulla una prenotazione", azione_annulla_prenotazione),
        ("Gestisci pagamenti", azione_pagamenti),
        ("Cambia password", azione_cambia_password),
    ],
    "organizzatore": [
        ("Visualizza eventi", azione_visualizza_eventi),
        ("Dettagli di un evento (con prenotazioni)", azione_dettagli_evento),
        ("Crea un nuovo evento", azione_crea_evento),
        ("Visualizza tutte le prenotazioni", azione_tutte_prenotazioni),
        ("Annulla una prenotazione", azione_annulla_prenotazione),
        ("Approva / rifiuta richieste workshop", azione_approva_workshop),
        ("Gestisci pagamenti", azione_pagamenti),
        ("Annulla un evento", azione_annulla_evento),
        ("Crea account collaboratore", azione_crea_collaboratore),
        ("Cambia password", azione_cambia_password),
    ],
}


def esegui(azione, db, utente):
    """Esegue un'azione mostrando in modo chiaro gli eventuali errori."""
    try:
        azione(db, utente)
    except ErroreGestione as errore:
        print(f"  ! Errore: {errore}")


def menu_utente(db, utente):
    """Menu mostrato dopo il login: le voci dipendono dal ruolo."""
    voci = MENU_PER_RUOLO[utente["ruolo"]]
    while True:
        print(f"\n--- Menu {utente['ruolo']} ({utente['username']}) ---")
        for i, (descrizione, _) in enumerate(voci, 1):
            print(f"{i:>2}. {descrizione}")
        print(" 0. Logout")
        scelta = chiedi_intero("Scelta: ", 0, len(voci))
        if scelta == 0:
            print("Logout effettuato.")
            return
        esegui(voci[scelta - 1][1], db, utente)


def chiedi_campo(domanda, controllo):
    """
    Chiede un campo e lo controlla subito con la funzione 'controllo':
    se il dato non è valido mostra l'errore e lo richiede.
    """
    while True:
        valore = chiedi_testo(domanda)
        try:
            return controllo(valore)
        except ErroreGestione as errore:
            print(f"  ! {errore}")


def chiedi_dati_account(db):
    """
    Chiede username, nome, email e password controllando ogni campo
    appena inserito. Restituisce (username, nome, email, password),
    oppure None se l'utente scrive 0 per annullare.
    """
    print("(scrivi 0 come username per annullare)")
    while True:
        username = chiedi_testo("Username (3-20 caratteri: lettere, numeri o _): ")
        if username == "0":
            print("Operazione annullata.")
            return None
        try:
            username = controlla_username(db, username)
            break
        except ErroreGestione as errore:
            print(f"  ! {errore}")
    nome = chiedi_campo("Nome e cognome: ", controlla_nome)
    email = chiedi_campo("Email: ", lambda e: controlla_email(db, e))
    while True:
        password = chiedi_password("Password (min. 6 caratteri, almeno una lettera e un numero): ")
        try:
            valida_password(password, username)
        except ErroreGestione as errore:
            print(f"  ! {errore}")
            continue
        if password == chiedi_password("Ripeti la password: "):
            return username, nome, email, password
        print("  ! Le password non coincidono, riprova.")


def azione_registrazione(db, _utente=None):
    print("\n--- Registrazione nuovo partecipante ---")
    dati = chiedi_dati_account(db)
    if dati is None:
        return
    registra_utente(db, *dati)
    print(f"Registrazione completata. Ora puoi fare il login come '{dati[0]}'.")


TENTATIVI_PRIMA_DELLA_PAUSA = 3
SECONDI_DI_PAUSA = 5


def azione_login(db, tentativi_falliti):
    """
    Esegue il login e restituisce (utente, tentativi_falliti).
    Dopo 3 tentativi sbagliati di fila il programma fa una pausa
    a ogni nuovo errore, per rendere lenti i tentativi "a caso".
    """
    try:
        utente = login(db, chiedi_testo("Username: "), chiedi_password())
    except ErroreGestione as errore:
        tentativi_falliti += 1
        print(f"  ! Errore: {errore}")
        if tentativi_falliti >= TENTATIVI_PRIMA_DELLA_PAUSA:
            print(f"  ! Troppi tentativi falliti: attendi {SECONDI_DI_PAUSA} secondi...")
            time.sleep(SECONDI_DI_PAUSA)
        return None, tentativi_falliti
    print(f"Benvenuto/a {utente['nome']}!")
    if utente["password_predefinita"]:
        print("  ATTENZIONE: stai usando la password predefinita. Cambiala dal menu (voce 'Cambia password').")
    return utente, 0


def menu_principale(db):
    tentativi_falliti = 0
    while True:
        print("\n===== GESTIONE EVENTI MUSICALI =====")
        print("1. Registrazione")
        print("2. Login")
        print("3. Visualizza eventi")
        print("4. Esci")
        scelta = chiedi_intero("Scelta: ", 1, 4)
        if scelta == 1:
            esegui(azione_registrazione, db, None)
        elif scelta == 2:
            utente, tentativi_falliti = azione_login(db, tentativi_falliti)
            if utente is not None:
                menu_utente(db, utente)
        elif scelta == 3:
            stampa_eventi(db)
        else:
            print("Arrivederci!")
            return


def avvia_programma():
    """Apre il file dei dati (creandolo se serve) e mostra il menu principale."""
    try:
        db = apri_archivio()
        if crea_organizzatore_predefinito(db):
            print("Primo avvio: creato il file dei dati e l'account organizzatore "
                  "'admin' (password 'admin123').")
            print("Cambia la password dopo il primo accesso.")
    except ErroreGestione as errore:
        print(f"  ! Errore: {errore}")
        print("Il programma si ferma per non sovrascrivere i dati. "
              "Controlla il file oppure spostalo per ripartire da zero.")
        return
    try:
        menu_principale(db)
    except (KeyboardInterrupt, EOFError):
        print("\nProgramma interrotto.")


# ===========================================================================
# 6. DATI DI ESEMPIO (python gestione_eventi.py --dati-esempio)
# ===========================================================================

def crea_dati_esempio(db):
    # --- Utenti (le password vengono salvate solo come hash) ---
    crea_organizzatore_predefinito(db)                      # admin / admin123
    admin = login(db, "admin", "admin123")
    crea_collaboratore(db, admin, "staff", "Luca Bianchi", "luca@eventi.local", "staff123")
    registra_utente(db, "mario", "Mario Rossi", "mario@email.it", "mario123")
    registra_utente(db, "giulia", "Giulia Verdi", "giulia@email.it", "giulia123")
    mario = login(db, "mario", "mario123")
    giulia = login(db, "giulia", "giulia123")

    # --- Eventi ---
    concerto = crea_evento(db, admin, "Concerto Rock d'Autunno", "concerto",
                           "14/11/2027 21:00", "Teatro Comunale", 30, 25.0,
                           "Serata con band emergenti del territorio.")
    workshop = crea_evento(db, admin, "Workshop di produzione musicale", "workshop",
                           "20/11/2027 15:00", "Sala prove Musica Viva", 8, 40.0,
                           "Introduzione a DAW, registrazione e mixaggio.")
    dj_set = crea_evento(db, admin, "DJ set sotto le stelle", "dj_set",
                         "28/11/2027 22:30", "Piazza Maggiore", 100, 0,
                         "Musica elettronica all'aperto, ingresso libero.")

    # --- Prenotazioni ---
    p1 = prenota_concerto(db, mario, concerto, [5, 6])       # 2 posti numerati
    prenota_concerto(db, giulia, concerto, [10])
    aggiorna_pagamento(db, admin, p1, "pagato")
    w1 = prenota_posti(db, mario, workshop, 1)               # in attesa
    prenota_posti(db, giulia, workshop, 2)                   # in attesa
    approva_prenotazione(db, admin, w1)
    prenota_posti(db, giulia, dj_set, 3)                     # confermata subito


def genera_dati_esempio():
    """Cancella il file dei dati attuale (dopo conferma) e lo ricrea con i dati dimostrativi."""
    if os.path.exists(PERCORSO_DATI):
        risposta = input("Il file dei dati esiste già e verrà sostituito. Continuare? (s/n): ")
        if risposta.strip().lower() not in ("s", "si", "sì"):
            print("Operazione annullata.")
            return
        os.remove(PERCORSO_DATI)
    db = apri_archivio()
    crea_dati_esempio(db)
    print(f"File con dati di esempio creato: {PERCORSO_DATI}")
    print("Account: admin/admin123 (organizzatore), staff/staff123 (collaboratore),")
    print("         mario/mario123 e giulia/giulia123 (partecipanti)")


# ===========================================================================
# 7. TEST AUTOMATICI (python gestione_eventi.py --test)
# ===========================================================================

DATA_FUTURA = "15/06/2030 21:00"


class BaseTest(unittest.TestCase):
    """Prepara un archivio vuoto (solo in memoria) con organizzatore, collaboratore e due partecipanti."""

    def setUp(self):
        self.db = apri_archivio(None)
        crea_organizzatore_predefinito(self.db)
        self.org = login(self.db, "admin", "admin123")
        crea_collaboratore(self.db, self.org, "staff", "Staff", "staff@test.it", "staff123")
        self.collab = login(self.db, "staff", "staff123")
        registra_utente(self.db, "anna", "Anna", "anna@test.it", "anna123")
        registra_utente(self.db, "bruno", "Bruno", "bruno@test.it", "bruno123")
        self.anna = login(self.db, "anna", "anna123")
        self.bruno = login(self.db, "bruno", "bruno123")

    def nuovo_evento(self, tipo, capienza=5, prezzo=10.0):
        return crea_evento(self.db, self.org, f"Evento {tipo}", tipo,
                           DATA_FUTURA, "Bologna", capienza, prezzo)


class TestUtenti(BaseTest):
    """Registrazione, login e password."""

    def errore(self, funzione, *argomenti):
        """Verifica che l'operazione venga rifiutata e restituisce il messaggio di errore."""
        with self.assertRaises(ErroreGestione) as contesto:
            funzione(self.db, *argomenti)
        return str(contesto.exception)

    # --- password ---
    def test_password_non_salvata_in_chiaro(self):
        riga = cerca_utente(self.db, "anna")
        self.assertNotEqual(riga["password_hash"], "anna123")
        self.assertNotIn("anna123", riga["password_hash"])
        self.assertEqual(len(riga["salt"]), 32)   # salt casuale di 16 byte

    def test_stessa_password_hash_diversi(self):
        """Grazie al salt, due utenti con la stessa password hanno hash diversi."""
        registra_utente(self.db, "carla", "Carla", "carla@test.it", "anna123")
        h1, h2 = (cerca_utente(self.db, u)["password_hash"] for u in ("anna", "carla"))
        self.assertNotEqual(h1, h2)

    def test_password_deboli_rifiutate(self):
        for pw in ("abc12", "      ", "solelettere", "123456", "nuovo1"):
            self.errore(registra_utente, "nuovo1", "Nuovo", "nuovo@test.it", pw)
        # "nuovo1" è valida come forma, ma è uguale allo username
        self.assertIn("uguale allo username",
                      self.errore(registra_utente, "nuovo1", "Nuovo", "nuovo@test.it", "NUOVO1"))

    # --- registrazione ---
    def test_registrazione_corretta(self):
        uid = registra_utente(self.db, "  Carla_99 ", "  Carla   Rossi ", " Carla@Test.IT ", "carla123")
        riga = self.db.trova("utenti", uid)
        self.assertEqual(riga["username"], "carla_99")      # minuscolo e senza spazi
        self.assertEqual(riga["nome"], "Carla Rossi")       # spazi in eccesso tolti
        self.assertEqual(riga["email"], "carla@test.it")
        self.assertEqual(riga["ruolo"], "partecipante")     # ruolo predefinito

    def test_username_duplicato_anche_con_maiuscole(self):
        self.assertIn("già in uso", self.errore(registra_utente, "anna", "A", "a1@test.it", "pass1234"))
        self.assertIn("già in uso", self.errore(registra_utente, "ANNA", "A", "a2@test.it", "pass1234"))

    def test_email_duplicata(self):
        self.assertIn("email", self.errore(registra_utente, "anna2", "Anna", "ANNA@test.it", "pass1234"))

    def test_dati_registrazione_non_validi(self):
        self.errore(registra_utente, "x", "Nome", "x@test.it", "pass1234")           # username corto
        self.errore(registra_utente, "con spazio", "Nome", "x@test.it", "pass1234")  # spazio
        self.errore(registra_utente, "àccento", "Nome", "x@test.it", "pass1234")     # accento
        self.errore(registra_utente, "nuovo", "Nome", "senza-chiocciola", "pass1234")
        self.errore(registra_utente, "nuovo", "Nome", "a@b", "pass1234")             # manca il dominio
        self.errore(registra_utente, "nuovo", "", "n@test.it", "pass1234")           # nome vuoto
        self.errore(registra_utente, "nuovo", "!!!", "n@test.it", "pass1234")        # nome senza lettere
        self.errore(registra_utente, "nuovo", "x" * 51, "n@test.it", "pass1234")     # nome troppo lungo
        self.errore(registra_utente, "nuovo", "Nome", "n@test.it", "pass1234", "admin")  # ruolo inesistente

    def test_solo_organizzatore_crea_collaboratori(self):
        for utente in (self.anna, self.collab):
            self.errore(crea_collaboratore, utente, "nuovo", "Nuovo", "n@test.it", "pass1234")

    # --- login ---
    def test_login_corretto(self):
        utente = login(self.db, "anna", "anna123")
        self.assertEqual((utente["username"], utente["ruolo"]), ("anna", "partecipante"))
        self.assertFalse(utente["password_predefinita"])

    def test_login_ignora_maiuscole_e_spazi_nello_username(self):
        self.assertEqual(login(self.db, "  ANNA ", "anna123")["username"], "anna")

    def test_login_password_distingue_maiuscole(self):
        self.errore(login, "anna", "ANNA123")

    def test_login_fallito_stesso_messaggio(self):
        """Username inesistente e password errata danno lo stesso messaggio."""
        m1 = self.errore(login, "anna", "sbagliata1")
        m2 = self.errore(login, "nessuno", "sbagliata1")
        m3 = self.errore(login, "anna", "")
        self.assertEqual(m1, m2)
        self.assertEqual(m1, m3)

    def test_avviso_password_predefinita(self):
        self.assertTrue(self.org["password_predefinita"])
        cambia_password(self.db, self.org, "admin123", "nuovaPw1")
        self.assertFalse(self.org["password_predefinita"])
        self.errore(login, "admin", "admin123")
        self.assertFalse(login(self.db, "admin", "nuovaPw1")["password_predefinita"])

    # --- cambio password ---
    def test_cambia_password(self):
        self.errore(cambia_password, self.anna, "sbagliata1", "nuova123")   # vecchia errata
        self.errore(cambia_password, self.anna, "anna123", "anna123")      # uguale alla vecchia
        self.errore(cambia_password, self.anna, "anna123", "corta")        # debole
        cambia_password(self.db, self.anna, "anna123", "nuova123")
        self.errore(login, "anna", "anna123")
        login(self.db, "anna", "nuova123")


class TestCreazioneEventi(BaseTest):
    def test_crea_concerto_con_posti_numerati(self):
        eid = self.nuovo_evento("concerto", capienza=20)
        self.assertEqual(posti_disponibili(self.db, eid), 20)
        self.assertEqual(posti_liberi_concerto(self.db, eid), list(range(1, 21)))

    def test_dj_set_sempre_gratuito(self):
        eid = self.nuovo_evento("dj_set", prezzo=15)
        self.assertEqual(ottieni_evento(self.db, eid)["prezzo"], 0)

    def test_solo_organizzatore_crea_eventi(self):
        for utente in (self.anna, self.collab):
            with self.assertRaises(ErroreGestione):
                crea_evento(self.db, utente, "X", "concerto", DATA_FUTURA, "Y", 10)

    def test_dati_evento_non_validi(self):
        with self.assertRaises(ErroreGestione):
            crea_evento(self.db, self.org, "X", "concerto", DATA_FUTURA, "Y", 0)
        with self.assertRaises(ErroreGestione):
            crea_evento(self.db, self.org, "X", "festival", DATA_FUTURA, "Y", 10)
        with self.assertRaises(ErroreGestione):
            crea_evento(self.db, self.org, "X", "concerto", "31/02/2030 20:00", "Y", 10)
        with self.assertRaises(ErroreGestione):
            crea_evento(self.db, self.org, "X", "concerto", "01/01/2020 20:00", "Y", 10)


class TestConcerto(BaseTest):
    def setUp(self):
        super().setUp()
        self.eid = self.nuovo_evento("concerto", capienza=5, prezzo=20)

    def test_prenotazione_piu_posti(self):
        pid = prenota_concerto(self.db, self.anna, self.eid, [1, 2, 3])
        p = ottieni_prenotazione(self.db, pid)
        self.assertEqual(p["stato"], "confermata")
        self.assertEqual(p["importo"], 60)
        self.assertEqual(p["stato_pagamento"], "non_pagato")
        self.assertEqual(posti_liberi_concerto(self.db, self.eid), [4, 5])

    def test_stesso_account_prenota_di_nuovo(self):
        prenota_concerto(self.db, self.anna, self.eid, [1])
        prenota_concerto(self.db, self.anna, self.eid, [2])
        self.assertEqual(len(elenca_prenotazioni_utente(self.db, self.anna)), 2)

    def test_posto_gia_occupato(self):
        prenota_concerto(self.db, self.anna, self.eid, [3])
        with self.assertRaises(ErroreGestione):
            prenota_concerto(self.db, self.bruno, self.eid, [3])

    def test_tutto_o_niente(self):
        """Se un posto è occupato non deve essere prenotato nemmeno quello libero."""
        prenota_concerto(self.db, self.anna, self.eid, [3])
        with self.assertRaises(ErroreGestione):
            prenota_concerto(self.db, self.bruno, self.eid, [2, 3])
        self.assertIn(2, posti_liberi_concerto(self.db, self.eid))
        self.assertEqual(len(elenca_prenotazioni_utente(self.db, self.bruno)), 0)

    def test_posto_inesistente(self):
        with self.assertRaises(ErroreGestione):
            prenota_concerto(self.db, self.anna, self.eid, [6])


class TestDjSet(BaseTest):
    def test_conferma_automatica_e_capienza(self):
        eid = self.nuovo_evento("dj_set", capienza=3)
        pid = prenota_posti(self.db, self.anna, eid, 2)
        p = ottieni_prenotazione(self.db, pid)
        self.assertEqual(p["stato"], "confermata")
        self.assertEqual(p["stato_pagamento"], "gratuito")
        with self.assertRaises(ErroreGestione):
            prenota_posti(self.db, self.bruno, eid, 2)     # ne resta solo 1
        prenota_posti(self.db, self.bruno, eid, 1)
        self.assertEqual(posti_disponibili(self.db, eid), 0)


class TestWorkshop(BaseTest):
    def setUp(self):
        super().setUp()
        self.eid = self.nuovo_evento("workshop", capienza=3, prezzo=30)

    def test_richiesta_in_attesa(self):
        pid = prenota_posti(self.db, self.anna, self.eid, 2)
        self.assertEqual(ottieni_prenotazione(self.db, pid)["stato"], "in_attesa")
        # finché non è approvata non occupa posti
        self.assertEqual(posti_disponibili(self.db, self.eid), 3)

    def test_approvazione_non_supera_capienza(self):
        p1 = prenota_posti(self.db, self.anna, self.eid, 2)
        p2 = prenota_posti(self.db, self.bruno, self.eid, 2)
        approva_prenotazione(self.db, self.org, p1)
        with self.assertRaises(ErroreGestione):
            approva_prenotazione(self.db, self.org, p2)   # 2 + 2 > 3
        self.assertEqual(posti_disponibili(self.db, self.eid), 1)

    def test_rifiuto(self):
        pid = prenota_posti(self.db, self.anna, self.eid, 1)
        rifiuta_prenotazione(self.db, self.org, pid)
        self.assertEqual(ottieni_prenotazione(self.db, pid)["stato"], "rifiutata")
        with self.assertRaises(ErroreGestione):
            approva_prenotazione(self.db, self.org, pid)  # non più in attesa

    def test_solo_organizzatore_approva(self):
        pid = prenota_posti(self.db, self.anna, self.eid, 1)
        for utente in (self.collab, self.anna):
            with self.assertRaises(ErroreGestione):
                approva_prenotazione(self.db, utente, pid)


class TestAnnullamenti(BaseTest):
    def test_annulla_prenotazione_libera_posti(self):
        eid = self.nuovo_evento("concerto", capienza=5)
        pid = prenota_concerto(self.db, self.anna, eid, [1, 2])
        annulla_prenotazione(self.db, self.anna, pid)
        self.assertEqual(ottieni_prenotazione(self.db, pid)["stato"], "annullata")
        self.assertEqual(posti_disponibili(self.db, eid), 5)
        prenota_concerto(self.db, self.bruno, eid, [1])   # il posto è di nuovo prenotabile

    def test_annulla_prenotazione_pagata(self):
        eid = self.nuovo_evento("concerto", capienza=5)
        pid = prenota_concerto(self.db, self.anna, eid, [1])
        aggiorna_pagamento(self.db, self.collab, pid, "pagato")
        annulla_prenotazione(self.db, self.anna, pid)
        self.assertEqual(ottieni_prenotazione(self.db, pid)["stato_pagamento"], "da_rimborsare")

    def test_partecipante_non_tocca_prenotazioni_altrui(self):
        eid = self.nuovo_evento("dj_set")
        pid = prenota_posti(self.db, self.anna, eid, 1)
        with self.assertRaises(ErroreGestione):
            annulla_prenotazione(self.db, self.bruno, pid)
        with self.assertRaises(ErroreGestione):
            elenca_tutte_prenotazioni(self.db, self.bruno)
        self.assertEqual(len(elenca_prenotazioni_utente(self.db, self.bruno)), 0)

    def test_doppio_annullamento(self):
        eid = self.nuovo_evento("dj_set")
        pid = prenota_posti(self.db, self.anna, eid, 1)
        annulla_prenotazione(self.db, self.anna, pid)
        with self.assertRaises(ErroreGestione):
            annulla_prenotazione(self.db, self.anna, pid)

    def test_annulla_evento_e_notifiche(self):
        eid = self.nuovo_evento("concerto", capienza=5)
        pid_anna = prenota_concerto(self.db, self.anna, eid, [1])
        prenota_concerto(self.db, self.anna, eid, [2])
        prenota_concerto(self.db, self.bruno, eid, [3])
        aggiorna_pagamento(self.db, self.org, pid_anna, "pagato")

        inviate = annulla_evento(self.db, self.org, eid)

        self.assertEqual(sorted(n[0] for n in inviate), ["anna", "bruno"])  # una notifica a testa
        self.assertEqual(len(notifiche_utente(self.db, self.anna)), 1)
        self.assertEqual(ottieni_evento(self.db, eid)["stato"], "annullato")
        stati = {p["stato"] for p in elenca_tutte_prenotazioni(self.db, self.org, eid)}
        self.assertEqual(stati, {"annullata"})
        self.assertEqual(ottieni_prenotazione(self.db, pid_anna)["stato_pagamento"], "da_rimborsare")
        with self.assertRaises(ErroreGestione):
            prenota_concerto(self.db, self.bruno, eid, [4])   # evento annullato

    def test_solo_organizzatore_annulla_evento(self):
        eid = self.nuovo_evento("dj_set")
        with self.assertRaises(ErroreGestione):
            annulla_evento(self.db, self.collab, eid)


class TestFileJson(unittest.TestCase):
    """Salvataggio e lettura del file JSON (usa una cartella temporanea)."""

    def setUp(self):
        self.cartella = tempfile.TemporaryDirectory()
        self.percorso = os.path.join(self.cartella.name, "dati.json")

    def tearDown(self):
        self.cartella.cleanup()

    def test_dati_salvati_e_ricaricati(self):
        db = apri_archivio(self.percorso)
        crea_organizzatore_predefinito(db)
        org = login(db, "admin", "admin123")
        registra_utente(db, "anna", "Anna", "anna@test.it", "anna123")
        eid = crea_evento(db, org, "Concerto", "concerto", DATA_FUTURA, "Bologna", 5, 10)
        pid = prenota_concerto(db, login(db, "anna", "anna123"), eid, [2, 3])

        # Si riapre il file da zero, come se il programma fosse stato chiuso e riavviato
        riaperto = apri_archivio(self.percorso)
        anna = login(riaperto, "anna", "anna123")
        self.assertEqual(ottieni_evento(riaperto, eid)["nome"], "Concerto")
        self.assertEqual(posti_liberi_concerto(riaperto, eid), [1, 4, 5])
        annulla_prenotazione(riaperto, anna, pid)
        self.assertEqual(posti_disponibili(apri_archivio(self.percorso), eid), 5)

    def test_file_json_leggibile_e_senza_password_in_chiaro(self):
        db = apri_archivio(self.percorso)
        crea_organizzatore_predefinito(db)
        with open(self.percorso, encoding="utf-8") as file:
            contenuto = file.read()
        dati = json.loads(contenuto)   # è JSON valido
        self.assertEqual(dati["utenti"][0]["username"], "admin")
        self.assertNotIn("admin123", contenuto)

    def test_id_non_riutilizzati(self):
        db = apri_archivio(self.percorso)
        crea_organizzatore_predefinito(db)
        id1 = registra_utente(db, "anna", "Anna", "anna@test.it", "anna123")
        id2 = registra_utente(apri_archivio(self.percorso), "bruno", "Bruno", "bruno@test.it", "bruno123")
        self.assertEqual(id2, id1 + 1)

    def test_file_rovinato_non_viene_sovrascritto(self):
        with open(self.percorso, "w", encoding="utf-8") as file:
            file.write("{ questo non è JSON")
        with self.assertRaises(ErroreGestione):
            apri_archivio(self.percorso)
        with open(self.percorso, encoding="utf-8") as file:
            self.assertEqual(file.read(), "{ questo non è JSON")

    def test_file_con_formato_sbagliato(self):
        with open(self.percorso, "w", encoding="utf-8") as file:
            json.dump({"utenti": "non una lista"}, file)
        with self.assertRaises(ErroreGestione):
            apri_archivio(self.percorso)


class TestPagamenti(BaseTest):
    def test_aggiorna_pagamento(self):
        eid = self.nuovo_evento("workshop", prezzo=30)
        pid = prenota_posti(self.db, self.anna, eid, 1)
        aggiorna_pagamento(self.db, self.collab, pid, "pagato")
        self.assertEqual(ottieni_prenotazione(self.db, pid)["stato_pagamento"], "pagato")

    def test_pagamento_gratuito_non_modificabile_e_permessi(self):
        eid = self.nuovo_evento("dj_set")
        pid = prenota_posti(self.db, self.anna, eid, 1)
        with self.assertRaises(ErroreGestione):
            aggiorna_pagamento(self.db, self.org, pid, "pagato")
        with self.assertRaises(ErroreGestione):
            aggiorna_pagamento(self.db, self.anna, pid, "pagato")


# ===========================================================================
# 8. AVVIO
# ===========================================================================

if __name__ == "__main__":
    if "--test" in sys.argv:
        unittest.main(argv=[sys.argv[0], "-v"])
    elif "--dati-esempio" in sys.argv:
        genera_dati_esempio()
    else:
        avvia_programma()
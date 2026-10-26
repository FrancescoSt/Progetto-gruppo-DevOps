"""
gestione_eventi.py
==================
Programma per la gestione di eventi musicali (concerti, workshop, DJ set),
prenotazioni, partecipanti e disponibilità dei posti.
Interfaccia da terminale, dati salvati in un database SQLite locale.

Uso:
    python gestione_eventi.py                 avvia il programma (menu)
    python gestione_eventi.py --dati-esempio  ricrea il database con dati dimostrativi
    python gestione_eventi.py --test          esegue i test automatici

Il file è diviso in sezioni:
    1. DATABASE      connessione e creazione delle tabelle
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
import os
import re
import sqlite3
import sys
import time
import unittest
from datetime import datetime



# ===========================================================================
# 1. DATABASE: connessione e creazione delle tabelle
# ===========================================================================

# Percorso del file del database (stessa cartella di questo file)
PERCORSO_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eventi_musicali.db")


class ErroreGestione(Exception):
    """
    Errore "previsto" causato da un'operazione non valida
    (es. posto già occupato, capienza superata, permessi insufficienti).
    Il messaggio è già scritto in modo comprensibile per l'utente.
    """


# Istruzioni SQL per creare le tabelle (solo se non esistono già)
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS utenti (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    nome          TEXT NOT NULL,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL,          -- hash della password, MAI la password in chiaro
    salt          TEXT NOT NULL,          -- valore casuale usato per l'hash
    ruolo         TEXT NOT NULL CHECK (ruolo IN ('organizzatore', 'collaboratore', 'partecipante'))
);

CREATE TABLE IF NOT EXISTS eventi (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nome        TEXT NOT NULL,
    tipo        TEXT NOT NULL CHECK (tipo IN ('concerto', 'workshop', 'dj_set')),
    data_ora    TEXT NOT NULL,            -- formato 'AAAA-MM-GG HH:MM'
    luogo       TEXT NOT NULL,
    descrizione TEXT NOT NULL DEFAULT '',
    capienza    INTEGER NOT NULL CHECK (capienza > 0),
    prezzo      REAL NOT NULL DEFAULT 0 CHECK (prezzo >= 0),
    stato       TEXT NOT NULL DEFAULT 'attivo' CHECK (stato IN ('attivo', 'annullato')),
    creato_da   INTEGER REFERENCES utenti(id)
);

CREATE TABLE IF NOT EXISTS prenotazioni (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    utente_id         INTEGER NOT NULL REFERENCES utenti(id),
    evento_id         INTEGER NOT NULL REFERENCES eventi(id),
    num_posti         INTEGER NOT NULL CHECK (num_posti > 0),
    stato             TEXT NOT NULL CHECK (stato IN ('in_attesa', 'confermata', 'rifiutata', 'annullata')),
    importo           REAL NOT NULL DEFAULT 0,
    stato_pagamento   TEXT NOT NULL CHECK (stato_pagamento IN
                          ('gratuito', 'non_pagato', 'pagato', 'da_rimborsare', 'rimborsato')),
    data_prenotazione TEXT NOT NULL
);

-- Posti numerati dei concerti: un posto è libero se prenotazione_id è NULL
CREATE TABLE IF NOT EXISTS posti (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evento_id       INTEGER NOT NULL REFERENCES eventi(id),
    numero          INTEGER NOT NULL,
    prenotazione_id INTEGER REFERENCES prenotazioni(id),
    UNIQUE (evento_id, numero)
);

-- Notifiche simulate (es. annullamento di un evento)
CREATE TABLE IF NOT EXISTS notifiche (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    utente_id  INTEGER NOT NULL REFERENCES utenti(id),
    evento_id  INTEGER NOT NULL REFERENCES eventi(id),
    messaggio  TEXT NOT NULL,
    data_invio TEXT NOT NULL
);
"""


def connetti(percorso=PERCORSO_DB):
    """
    Apre la connessione al database e crea le tabelle se mancano.
    Con percorso=":memory:" crea un database temporaneo in memoria (usato nei test).
    """
    conn = sqlite3.connect(percorso)
    conn.row_factory = sqlite3.Row          # permette di leggere le colonne per nome: riga["nome"]
    conn.execute("PRAGMA foreign_keys = ON")  # attiva il controllo delle chiavi esterne
    crea_tabelle(conn)
    return conn


def crea_tabelle(conn):
    """Crea tutte le tabelle del programma (se non esistono già)."""
    conn.executescript(SCHEMA_SQL)
    conn.commit()


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


def controlla_username(conn, username):
    username = normalizza_username(username)
    if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
        raise ErroreGestione("Lo username deve avere da 3 a 20 caratteri (lettere senza accenti, numeri o _).")
    if conn.execute("SELECT 1 FROM utenti WHERE lower(username) = ?", (username,)).fetchone():
        raise ErroreGestione(f"Lo username '{username}' è già in uso.")
    return username


def controlla_nome(nome):
    nome = " ".join((nome or "").split())   # toglie gli spazi in eccesso
    if not 2 <= len(nome) <= 50:
        raise ErroreGestione("Il nome deve avere da 2 a 50 caratteri.")
    if not any(c.isalpha() for c in nome):
        raise ErroreGestione("Il nome deve contenere almeno una lettera.")
    return nome


def controlla_email(conn, email):
    email = (email or "").strip().lower()
    if len(email) > 100 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ErroreGestione("Indirizzo email non valido (esempio: nome@dominio.it).")
    if conn.execute("SELECT 1 FROM utenti WHERE lower(email) = ?", (email,)).fetchone():
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

def registra_utente(conn, username, nome, email, password, ruolo="partecipante"):
    """
    Registra un nuovo utente e ne restituisce l'id.
    Dal menu pubblico si possono registrare solo partecipanti;
    i collaboratori vengono creati dall'organizzatore (vedi crea_collaboratore).
    """
    if ruolo not in RUOLI:
        raise ErroreGestione("Ruolo non valido.")
    username = controlla_username(conn, username)
    nome = controlla_nome(nome)
    email = controlla_email(conn, email)
    valida_password(password, username)

    hash_pw, salt = calcola_hash_password(password)
    try:
        with conn:  # transazione: salva tutto o niente
            cur = conn.execute(
                "INSERT INTO utenti (username, nome, email, password_hash, salt, ruolo) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (username, nome, email, hash_pw, salt, ruolo))
    except sqlite3.IntegrityError:
        # caso raro: lo stesso username è stato registrato nello stesso istante
        raise ErroreGestione(f"Lo username '{username}' è già in uso.")
    return cur.lastrowid


# Hash "finto" usato quando lo username non esiste: così il login impiega
# lo stesso tempo e non si può capire quali username sono registrati.
_SALT_FINTO = os.urandom(16).hex()
_HASH_FINTO, _ = calcola_hash_password("password-inesistente", _SALT_FINTO)


def login(conn, username, password):
    """
    Verifica le credenziali. Restituisce un dizionario con i dati dell'utente
    (id, username, nome, ruolo, password_predefinita) oppure solleva ErroreGestione.
    """
    username = normalizza_username(username)
    riga = conn.execute("SELECT * FROM utenti WHERE lower(username) = ?", (username,)).fetchone()
    if riga is None:
        verifica_password(password or "", _HASH_FINTO, _SALT_FINTO)  # stesso tempo di calcolo
        raise ErroreGestione("Username o password errati.")
    # Stesso messaggio per username o password errati: non si rivela quale dei due è sbagliato
    if not verifica_password(password or "", riga["password_hash"], riga["salt"]):
        raise ErroreGestione("Username o password errati.")
    d = ORGANIZZATORE_PREDEFINITO
    return {"id": riga["id"], "username": riga["username"],
            "nome": riga["nome"], "ruolo": riga["ruolo"],
            "password_predefinita": username == d["username"] and password == d["password"]}


def cambia_password(conn, utente, vecchia_password, nuova_password):
    """Permette all'utente autenticato di cambiare la propria password."""
    riga = conn.execute("SELECT * FROM utenti WHERE id = ?", (utente["id"],)).fetchone()
    if not verifica_password(vecchia_password or "", riga["password_hash"], riga["salt"]):
        raise ErroreGestione("La password attuale non è corretta.")
    if nuova_password == vecchia_password:
        raise ErroreGestione("La nuova password deve essere diversa da quella attuale.")
    valida_password(nuova_password, riga["username"])
    hash_pw, salt = calcola_hash_password(nuova_password)
    with conn:
        conn.execute("UPDATE utenti SET password_hash = ?, salt = ? WHERE id = ?",
                     (hash_pw, salt, utente["id"]))
    utente["password_predefinita"] = False


def crea_collaboratore(conn, utente, username, nome, email, password):
    """Solo l'organizzatore può creare account di tipo collaboratore."""
    richiedi_ruolo(utente, "organizzatore")
    return registra_utente(conn, username, nome, email, password, ruolo="collaboratore")


def crea_organizzatore_predefinito(conn):
    """
    Al primo avvio non esiste nessun organizzatore: ne viene creato uno
    predefinito, così è possibile accedere e creare gli eventi.
    Restituisce True se l'account è stato creato ora.
    """
    esiste = conn.execute("SELECT 1 FROM utenti WHERE ruolo = 'organizzatore'").fetchone()
    if esiste:
        return False
    d = ORGANIZZATORE_PREDEFINITO
    registra_utente(conn, d["username"], d["nome"], d["email"], d["password"], "organizzatore")
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

TIPI_EVENTO = {"concerto": "Concerto", "workshop": "Workshop", "dj_set": "DJ set"}
FORMATO_DB = "%Y-%m-%d %H:%M"          # come la data viene salvata nel database
FORMATO_UTENTE = "%d/%m/%Y %H:%M"      # come la data viene scritta/letta dall'utente
CAPIENZA_MASSIMA = 10_000


# ---------------------------------------------------------------------------
# Date
# ---------------------------------------------------------------------------

def converti_data(testo):
    """Converte 'GG/MM/AAAA HH:MM' nel formato del database. Solleva errore se non valida."""
    try:
        data = datetime.strptime((testo or "").strip(), FORMATO_UTENTE)
    except ValueError:
        raise ErroreGestione("Data non valida. Usa il formato GG/MM/AAAA HH:MM (es. 15/03/2027 21:00).")
    return data.strftime(FORMATO_DB)


def formatta_data(data_db):
    """Converte la data del database nel formato leggibile dall'utente."""
    return datetime.strptime(data_db, FORMATO_DB).strftime(FORMATO_UTENTE)


def evento_passato(evento):
    return datetime.strptime(evento["data_ora"], FORMATO_DB) < datetime.now()


# ---------------------------------------------------------------------------
# Creazione e lettura degli eventi
# ---------------------------------------------------------------------------

def crea_evento(conn, utente, nome, tipo, data_ora, luogo, capienza, prezzo=0.0, descrizione=""):
    """
    Crea un nuovo evento (solo organizzatore) e ne restituisce l'id.
    data_ora deve essere nel formato 'GG/MM/AAAA HH:MM'.
    Per i concerti vengono creati automaticamente i posti numerati 1..capienza.
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
    data_db = converti_data(data_ora)
    if datetime.strptime(data_db, FORMATO_DB) < datetime.now():
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

    with conn:  # transazione: evento e posti vengono salvati insieme
        cur = conn.execute(
            "INSERT INTO eventi (nome, tipo, data_ora, luogo, descrizione, capienza, prezzo, creato_da) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (nome, tipo, data_db, luogo, (descrizione or "").strip(), capienza, prezzo, utente["id"]))
        evento_id = cur.lastrowid
        if tipo == "concerto":
            conn.executemany("INSERT INTO posti (evento_id, numero) VALUES (?, ?)",
                             [(evento_id, n) for n in range(1, capienza + 1)])
    return evento_id


def ottieni_evento(conn, evento_id):
    """Restituisce la riga dell'evento oppure solleva un errore se non esiste."""
    evento = conn.execute("SELECT * FROM eventi WHERE id = ?", (evento_id,)).fetchone()
    if evento is None:
        raise ErroreGestione(f"Nessun evento con id {evento_id}.")
    return evento


def posti_occupati(conn, evento_id):
    """Numero di posti occupati: conta solo le prenotazioni confermate."""
    riga = conn.execute(
        "SELECT COALESCE(SUM(num_posti), 0) FROM prenotazioni "
        "WHERE evento_id = ? AND stato = 'confermata'", (evento_id,)).fetchone()
    return riga[0]


def posti_disponibili(conn, evento_id):
    """Numero di posti ancora prenotabili per un evento."""
    evento = ottieni_evento(conn, evento_id)
    if evento["tipo"] == "concerto":
        return len(posti_liberi_concerto(conn, evento_id))
    return evento["capienza"] - posti_occupati(conn, evento_id)


def posti_liberi_concerto(conn, evento_id):
    """Elenco dei numeri di posto ancora liberi di un concerto."""
    righe = conn.execute(
        "SELECT numero FROM posti WHERE evento_id = ? AND prenotazione_id IS NULL ORDER BY numero",
        (evento_id,)).fetchall()
    return [r["numero"] for r in righe]


def elenca_eventi(conn, includi_annullati=False):
    """Restituisce gli eventi ordinati per data, con i posti disponibili calcolati."""
    sql = "SELECT * FROM eventi"
    if not includi_annullati:
        sql += " WHERE stato = 'attivo'"
    sql += " ORDER BY data_ora"
    risultato = []
    for evento in conn.execute(sql).fetchall():
        dati = dict(evento)
        dati["disponibili"] = posti_disponibili(conn, evento["id"])
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

def annulla_evento(conn, utente, evento_id):
    """
    Annulla un evento (solo organizzatore):
    - l'evento passa allo stato 'annullato';
    - tutte le prenotazioni attive vengono annullate e i posti liberati;
    - i pagamenti già effettuati diventano 'da_rimborsare';
    - ogni partecipante interessato riceve una notifica simulata.
    Restituisce l'elenco delle notifiche inviate (username, messaggio).
    """
    richiedi_ruolo(utente, "organizzatore")
    evento = ottieni_evento(conn, evento_id)
    if evento["stato"] == "annullato":
        raise ErroreGestione("L'evento è già stato annullato.")

    # Partecipanti con almeno una prenotazione attiva (in attesa o confermata)
    interessati = conn.execute(
        "SELECT DISTINCT u.id, u.username, u.nome, u.email FROM prenotazioni p "
        "JOIN utenti u ON u.id = p.utente_id "
        "WHERE p.evento_id = ? AND p.stato IN ('in_attesa', 'confermata')",
        (evento_id,)).fetchall()

    adesso = datetime.now().strftime(FORMATO_DB)
    messaggio = (f"L'evento '{evento['nome']}' del {formatta_data(evento['data_ora'])} "
                 f"presso {evento['luogo']} è stato annullato. "
                 f"Le tue prenotazioni sono state annullate; eventuali pagamenti saranno rimborsati.")
    inviate = []

    with conn:
        conn.execute("UPDATE eventi SET stato = 'annullato' WHERE id = ?", (evento_id,))
        conn.execute(
            "UPDATE prenotazioni SET stato_pagamento = 'da_rimborsare' "
            "WHERE evento_id = ? AND stato IN ('in_attesa', 'confermata') AND stato_pagamento = 'pagato'",
            (evento_id,))
        conn.execute(
            "UPDATE prenotazioni SET stato = 'annullata' "
            "WHERE evento_id = ? AND stato IN ('in_attesa', 'confermata')", (evento_id,))
        conn.execute("UPDATE posti SET prenotazione_id = NULL WHERE evento_id = ?", (evento_id,))
        for p in interessati:
            conn.execute(
                "INSERT INTO notifiche (utente_id, evento_id, messaggio, data_invio) VALUES (?, ?, ?, ?)",
                (p["id"], evento_id, messaggio, adesso))
            inviate.append((p["username"], p["email"], messaggio))
    return inviate


def notifiche_utente(conn, utente):
    """Notifiche ricevute dall'utente autenticato (dalla più recente)."""
    return conn.execute(
        "SELECT * FROM notifiche WHERE utente_id = ? ORDER BY id DESC", (utente["id"],)).fetchall()


# ===========================================================================
# 4. PRENOTAZIONI: prenotazioni, workshop e pagamenti
# ===========================================================================

STATI_PAGAMENTO_MODIFICABILI = ("non_pagato", "pagato", "da_rimborsare", "rimborsato")
STAFF = ("organizzatore", "collaboratore")


# ---------------------------------------------------------------------------
# Funzioni di supporto
# ---------------------------------------------------------------------------

def _controlla_evento_prenotabile(conn, evento_id):
    """Verifica che l'evento esista, sia attivo e non sia già passato."""
    evento = ottieni_evento(conn, evento_id)
    if evento["stato"] != "attivo":
        raise ErroreGestione("L'evento è stato annullato: non è possibile prenotare.")
    if evento_passato(evento):
        raise ErroreGestione("L'evento si è già svolto: non è possibile prenotare.")
    return evento


def _stato_pagamento_iniziale(importo):
    return "gratuito" if importo == 0 else "non_pagato"


def _inserisci_prenotazione(conn, utente_id, evento_id, num_posti, stato, importo):
    cur = conn.execute(
        "INSERT INTO prenotazioni (utente_id, evento_id, num_posti, stato, importo, "
        "stato_pagamento, data_prenotazione) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (utente_id, evento_id, num_posti, stato, importo,
         _stato_pagamento_iniziale(importo), datetime.now().strftime(FORMATO_DB)))
    return cur.lastrowid


def ottieni_prenotazione(conn, prenotazione_id):
    p = conn.execute("SELECT * FROM prenotazioni WHERE id = ?", (prenotazione_id,)).fetchone()
    if p is None:
        raise ErroreGestione(f"Nessuna prenotazione con id {prenotazione_id}.")
    return p


def numeri_posti_prenotazione(conn, prenotazione_id):
    """Numeri dei posti (concerti) assegnati a una prenotazione."""
    righe = conn.execute("SELECT numero FROM posti WHERE prenotazione_id = ? ORDER BY numero",
                         (prenotazione_id,)).fetchall()
    return [r["numero"] for r in righe]


# ---------------------------------------------------------------------------
# Prenotazione
# ---------------------------------------------------------------------------

def prenota_concerto(conn, utente, evento_id, numeri_posti):
    """
    Prenota uno o più posti numerati di un concerto.
    Se anche un solo posto non è disponibile, non viene prenotato nulla.
    Restituisce l'id della prenotazione (confermata).
    """
    richiedi_ruolo(utente, "partecipante")
    evento = _controlla_evento_prenotabile(conn, evento_id)
    if evento["tipo"] != "concerto":
        raise ErroreGestione("Questo evento non ha posti numerati.")

    numeri = sorted(set(numeri_posti or []))
    if not numeri:
        raise ErroreGestione("Indica almeno un posto da prenotare.")
    for n in numeri:
        if not 1 <= n <= evento["capienza"]:
            raise ErroreGestione(f"Il posto {n} non esiste (posti da 1 a {evento['capienza']}).")

    importo = round(evento["prezzo"] * len(numeri), 2)
    with conn:  # transazione: in caso di errore viene annullato tutto (rollback)
        prenotazione_id = _inserisci_prenotazione(conn, utente["id"], evento_id,
                                                  len(numeri), "confermata", importo)
        for n in numeri:
            # Il posto viene assegnato solo se è ancora libero (prenotazione_id IS NULL)
            cur = conn.execute(
                "UPDATE posti SET prenotazione_id = ? "
                "WHERE evento_id = ? AND numero = ? AND prenotazione_id IS NULL",
                (prenotazione_id, evento_id, n))
            if cur.rowcount == 0:
                raise ErroreGestione(f"Il posto {n} è già occupato. Nessun posto è stato prenotato.")
    return prenotazione_id


def prenota_posti(conn, utente, evento_id, num_posti):
    """
    Prenota un certo numero di posti per un workshop o un DJ set.
    - Workshop: la prenotazione resta 'in_attesa' finché l'organizzatore non la approva.
    - DJ set:   la prenotazione è confermata subito se ci sono posti.
    Restituisce l'id della prenotazione.
    """
    richiedi_ruolo(utente, "partecipante")
    evento = _controlla_evento_prenotabile(conn, evento_id)
    if evento["tipo"] == "concerto":
        raise ErroreGestione("Per i concerti bisogna scegliere i posti numerati.")
    if not isinstance(num_posti, int) or num_posti < 1:
        raise ErroreGestione("Il numero di posti deve essere almeno 1.")

    liberi = posti_disponibili(conn, evento_id)
    if num_posti > liberi:
        raise ErroreGestione(f"Posti insufficienti: richiesti {num_posti}, disponibili {liberi}.")

    stato = "in_attesa" if evento["tipo"] == "workshop" else "confermata"
    importo = round(evento["prezzo"] * num_posti, 2)
    with conn:
        return _inserisci_prenotazione(conn, utente["id"], evento_id, num_posti, stato, importo)


# ---------------------------------------------------------------------------
# Consultazione
# ---------------------------------------------------------------------------

SQL_PRENOTAZIONI = """
    SELECT p.*, e.nome AS nome_evento, e.tipo AS tipo_evento, e.data_ora, e.stato AS stato_evento,
           u.username
    FROM prenotazioni p
    JOIN eventi e ON e.id = p.evento_id
    JOIN utenti u ON u.id = p.utente_id
"""


def elenca_prenotazioni_utente(conn, utente):
    """Prenotazioni dell'utente autenticato (un partecipante vede SOLO le proprie)."""
    return conn.execute(SQL_PRENOTAZIONI + " WHERE p.utente_id = ? ORDER BY p.id",
                        (utente["id"],)).fetchall()


def elenca_tutte_prenotazioni(conn, utente, evento_id=None):
    """Tutte le prenotazioni (eventualmente di un solo evento): solo organizzatore e collaboratore."""
    richiedi_ruolo(utente, *STAFF)
    if evento_id is None:
        return conn.execute(SQL_PRENOTAZIONI + " ORDER BY p.id").fetchall()
    return conn.execute(SQL_PRENOTAZIONI + " WHERE p.evento_id = ? ORDER BY p.id",
                        (evento_id,)).fetchall()


# ---------------------------------------------------------------------------
# Annullamento di una prenotazione
# ---------------------------------------------------------------------------

def annulla_prenotazione(conn, utente, prenotazione_id):
    """
    Annulla una prenotazione in attesa o confermata e libera i posti.
    Un partecipante può annullare solo le proprie prenotazioni;
    organizzatore e collaboratore possono annullare qualsiasi prenotazione.
    Se era già stata pagata, il pagamento diventa 'da_rimborsare'.
    """
    richiedi_ruolo(utente, "partecipante", *STAFF)
    p = ottieni_prenotazione(conn, prenotazione_id)

    if utente["ruolo"] == "partecipante" and p["utente_id"] != utente["id"]:
        # Stesso messaggio di "non esiste": non si rivelano le prenotazioni altrui
        raise ErroreGestione(f"Nessuna prenotazione con id {prenotazione_id}.")
    if p["stato"] not in ("in_attesa", "confermata"):
        raise ErroreGestione(f"La prenotazione è già nello stato '{p['stato']}' e non può essere annullata.")

    nuovo_pagamento = "da_rimborsare" if p["stato_pagamento"] == "pagato" else p["stato_pagamento"]
    with conn:
        conn.execute("UPDATE prenotazioni SET stato = 'annullata', stato_pagamento = ? WHERE id = ?",
                     (nuovo_pagamento, prenotazione_id))
        conn.execute("UPDATE posti SET prenotazione_id = NULL WHERE prenotazione_id = ?",
                     (prenotazione_id,))


# ---------------------------------------------------------------------------
# Approvazione dei workshop (solo organizzatore)
# ---------------------------------------------------------------------------

def richieste_workshop_in_attesa(conn, utente):
    richiedi_ruolo(utente, "organizzatore")
    return conn.execute(SQL_PRENOTAZIONI + " WHERE p.stato = 'in_attesa' AND e.stato = 'attivo' "
                                           "ORDER BY p.id").fetchall()


def _richiesta_workshop(conn, utente, prenotazione_id):
    richiedi_ruolo(utente, "organizzatore")
    p = ottieni_prenotazione(conn, prenotazione_id)
    evento = ottieni_evento(conn, p["evento_id"])
    if evento["tipo"] != "workshop":
        raise ErroreGestione("Solo le prenotazioni dei workshop richiedono approvazione.")
    if p["stato"] != "in_attesa":
        raise ErroreGestione(f"La richiesta non è in attesa (stato attuale: '{p['stato']}').")
    return p, evento


def approva_prenotazione(conn, utente, prenotazione_id):
    """Approva una richiesta di workshop solo se c'è ancora capienza sufficiente."""
    p, evento = _richiesta_workshop(conn, utente, prenotazione_id)
    liberi = posti_disponibili(conn, evento["id"])
    if p["num_posti"] > liberi:
        raise ErroreGestione(
            f"Impossibile approvare: la richiesta è di {p['num_posti']} posti "
            f"ma ne restano solo {liberi}. Puoi rifiutarla.")
    with conn:
        conn.execute("UPDATE prenotazioni SET stato = 'confermata' WHERE id = ?", (prenotazione_id,))


def rifiuta_prenotazione(conn, utente, prenotazione_id):
    """Rifiuta una richiesta di workshop."""
    _richiesta_workshop(conn, utente, prenotazione_id)
    with conn:
        conn.execute("UPDATE prenotazioni SET stato = 'rifiutata' WHERE id = ?", (prenotazione_id,))


# ---------------------------------------------------------------------------
# Pagamenti (organizzatore e collaboratore)
# ---------------------------------------------------------------------------

def aggiorna_pagamento(conn, utente, prenotazione_id, nuovo_stato):
    """Aggiorna lo stato del pagamento di una prenotazione (registrazione manuale, non online)."""
    richiedi_ruolo(utente, *STAFF)
    if nuovo_stato not in STATI_PAGAMENTO_MODIFICABILI:
        raise ErroreGestione("Stato di pagamento non valido.")
    p = ottieni_prenotazione(conn, prenotazione_id)
    if p["stato_pagamento"] == "gratuito":
        raise ErroreGestione("La prenotazione è gratuita: non c'è nessun pagamento da gestire.")
    if p["stato"] in ("annullata", "rifiutata") and nuovo_stato == "pagato":
        raise ErroreGestione("Non si può segnare come pagata una prenotazione annullata o rifiutata.")
    with conn:
        conn.execute("UPDATE prenotazioni SET stato_pagamento = ? WHERE id = ?",
                     (nuovo_stato, prenotazione_id))


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
            data_db = converti_data(testo)
        except ErroreGestione as errore:
            print(f"  ! {errore}")
            continue
        if datetime.strptime(data_db, FORMATO_DB) < datetime.now():
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

def stampa_eventi(conn, includi_annullati=False):
    elenco = elenca_eventi(conn, includi_annullati)
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


def stampa_prenotazioni(conn, elenco, mostra_utente=False):
    if not elenco:
        print("\nNessuna prenotazione trovata.")
        return
    print()
    for p in elenco:
        dettaglio = f"{p['num_posti']} posto/i"
        if p["tipo_evento"] == "concerto":
            numeri = numeri_posti_prenotazione(conn, p["id"])
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

def azione_visualizza_eventi(conn, utente):
    staff = utente is not None and utente["ruolo"] in STAFF
    stampa_eventi(conn, includi_annullati=staff)


def azione_dettagli_evento(conn, utente):
    evento = ottieni_evento(conn, chiedi_intero("ID dell'evento: "))
    print(f"\n=== {evento['nome']} ===")
    print(f"Tipo:        {TIPI_EVENTO[evento['tipo']]}")
    print(f"Data e ora:  {formatta_data(evento['data_ora'])}")
    print(f"Luogo:       {evento['luogo']}")
    if evento["descrizione"]:
        print(f"Descrizione: {evento['descrizione']}")
    prezzo = "gratuito" if evento["prezzo"] == 0 else f"€{evento['prezzo']:.2f} a posto"
    print(f"Prezzo:      {prezzo}")
    print(f"Stato:       {evento['stato']}")
    print(f"Capienza:    {evento['capienza']} | disponibili: {posti_disponibili(conn, evento['id'])}")
    if evento["tipo"] == "concerto" and evento["stato"] == "attivo":
        print(f"Posti liberi: {formatta_intervalli(posti_liberi_concerto(conn, evento['id']))}")
    if evento["tipo"] == "workshop":
        print("Nota: le prenotazioni devono essere approvate dall'organizzatore.")
    if utente is not None and utente["ruolo"] in STAFF:
        print("\nPrenotazioni dell'evento:")
        stampa_prenotazioni(conn, elenca_tutte_prenotazioni(conn, utente, evento["id"]), True)


def azione_cambia_password(conn, utente):
    vecchia = chiedi_password("Password attuale: ")
    nuova = chiedi_password("Nuova password (min. 6 caratteri, almeno una lettera e un numero): ")
    if nuova != chiedi_password("Ripeti la nuova password: "):
        print("  ! Le password non coincidono.")
        return
    cambia_password(conn, utente, vecchia, nuova)
    print("Password aggiornata.")


# ---------------------------------------------------------------------------
# Azioni del partecipante
# ---------------------------------------------------------------------------

def azione_prenota(conn, utente):
    stampa_eventi(conn)
    evento = ottieni_evento(conn, chiedi_intero("\nID dell'evento da prenotare: "))
    if evento["tipo"] == "concerto":
        liberi = posti_liberi_concerto(conn, evento["id"])
        print(f"Posti liberi: {formatta_intervalli(liberi)}")
        numeri = chiedi_lista_posti("Posti da prenotare (es. 5  oppure  3,4  oppure  10-12): ")
        non_liberi = sorted(set(numeri) - set(liberi))
        if non_liberi:
            print(f"  ! Posti non disponibili: {', '.join(map(str, non_liberi))}. Nessun posto prenotato.")
            return
        totale = evento["prezzo"] * len(set(numeri))
        if not conferma(f"Confermi {len(set(numeri))} posto/i per un totale di €{totale:.2f}?"):
            return
        pid = prenota_concerto(conn, utente, evento["id"], numeri)
        print(f"Prenotazione #{pid} confermata.")
    else:
        disponibili = posti_disponibili(conn, evento["id"])
        print(f"Posti disponibili: {disponibili}")
        num = chiedi_intero("Quanti posti vuoi prenotare? ", 1)
        pid = prenota_posti(conn, utente, evento["id"], num)
        if evento["tipo"] == "workshop":
            print(f"Richiesta #{pid} inviata: è in attesa di approvazione dell'organizzatore.")
        else:
            print(f"Prenotazione #{pid} confermata (ingresso gratuito).")


def azione_mie_prenotazioni(conn, utente):
    stampa_prenotazioni(conn, elenca_prenotazioni_utente(conn, utente))


def azione_annulla_prenotazione(conn, utente):
    if utente["ruolo"] == "partecipante":
        azione_mie_prenotazioni(conn, utente)
    else:
        stampa_prenotazioni(conn, elenca_tutte_prenotazioni(conn, utente), True)
    pid = chiedi_intero("\nID della prenotazione da annullare (0 = indietro): ", 0)
    if pid == 0 or not conferma(f"Annullare la prenotazione #{pid}?"):
        return
    annulla_prenotazione(conn, utente, pid)
    print(f"Prenotazione #{pid} annullata. I posti sono di nuovo disponibili.")


def azione_mie_notifiche(conn, utente):
    elenco = notifiche_utente(conn, utente)
    if not elenco:
        print("\nNessuna notifica.")
    for n in elenco:
        print(f"\n[{formatta_data(n['data_invio'])}] {n['messaggio']}")


# ---------------------------------------------------------------------------
# Azioni di organizzatore e collaboratore
# ---------------------------------------------------------------------------

def azione_tutte_prenotazioni(conn, utente):
    stampa_prenotazioni(conn, elenca_tutte_prenotazioni(conn, utente), True)


def azione_crea_evento(conn, utente):
    print("\nTipo di evento:  1) Concerto   2) Workshop   3) DJ set")
    tipo = ("concerto", "workshop", "dj_set")[chiedi_intero("Scelta: ", 1, 3) - 1]
    nome = chiedi_testo("Nome evento: ")
    data = chiedi_data("Data e ora (GG/MM/AAAA HH:MM): ")
    luogo = chiedi_testo("Luogo: ")
    descrizione = chiedi_testo("Descrizione (facoltativa): ", obbligatorio=False)
    etichetta = "Numero di posti numerati" if tipo == "concerto" else "Capienza massima"
    capienza = chiedi_intero(f"{etichetta}: ", 1, CAPIENZA_MASSIMA)
    prezzo = 0.0 if tipo == "dj_set" else chiedi_decimale("Prezzo a posto in € (0 = gratuito): ")
    eid = crea_evento(conn, utente, nome, tipo, data, luogo, capienza, prezzo, descrizione)
    print(f"Evento #{eid} creato.")


def azione_approva_workshop(conn, utente):
    richieste = richieste_workshop_in_attesa(conn, utente)
    if not richieste:
        print("\nNessuna richiesta in attesa.")
        return
    for r in richieste:
        print(f"#{r['id']:<4} {r['nome_evento']} | utente: {r['username']} | posti richiesti: {r['num_posti']} "
              f"| liberi: {posti_disponibili(conn, r['evento_id'])}")
    pid = chiedi_intero("\nID della richiesta (0 = indietro): ", 0)
    if pid == 0:
        return
    scelta = chiedi_intero("1) Approva   2) Rifiuta : ", 1, 2)
    if scelta == 1:
        approva_prenotazione(conn, utente, pid)
        print(f"Richiesta #{pid} approvata.")
    else:
        rifiuta_prenotazione(conn, utente, pid)
        print(f"Richiesta #{pid} rifiutata.")


def azione_pagamenti(conn, utente):
    elenco = [p for p in elenca_tutte_prenotazioni(conn, utente)
              if p["stato_pagamento"] != "gratuito"]
    stampa_prenotazioni(conn, elenco, True)
    if not elenco:
        return
    pid = chiedi_intero("\nID della prenotazione da aggiornare (0 = indietro): ", 0)
    if pid == 0:
        return
    stati = STATI_PAGAMENTO_MODIFICABILI
    for i, s in enumerate(stati, 1):
        print(f"  {i}) {ETICHETTE_STATO[s]}")
    nuovo = stati[chiedi_intero("Nuovo stato del pagamento: ", 1, len(stati)) - 1]
    aggiorna_pagamento(conn, utente, pid, nuovo)
    print(f"Pagamento della prenotazione #{pid} aggiornato a '{ETICHETTE_STATO[nuovo]}'.")


def azione_annulla_evento(conn, utente):
    stampa_eventi(conn)
    eid = chiedi_intero("\nID dell'evento da annullare (0 = indietro): ", 0)
    if eid == 0:
        return
    evento = ottieni_evento(conn, eid)
    if not conferma(f"Annullare definitivamente '{evento['nome']}'?"):
        return
    inviate = annulla_evento(conn, utente, eid)
    print(f"Evento '{evento['nome']}' annullato.")
    print(f"Notifiche inviate (simulazione): {len(inviate)}")
    for username, email, messaggio in inviate:
        print(f"  [NOTIFICA -> {username} <{email}>] {messaggio}")


def azione_crea_collaboratore(conn, utente):
    print("\n--- Nuovo account collaboratore ---")
    dati = chiedi_dati_account(conn)
    if dati is None:
        return
    crea_collaboratore(conn, utente, *dati)
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


def esegui(azione, conn, utente):
    """Esegue un'azione mostrando in modo chiaro gli eventuali errori."""
    try:
        azione(conn, utente)
    except ErroreGestione as errore:
        print(f"  ! Errore: {errore}")


def menu_utente(conn, utente):
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
        esegui(voci[scelta - 1][1], conn, utente)


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


def chiedi_dati_account(conn):
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
            username = controlla_username(conn, username)
            break
        except ErroreGestione as errore:
            print(f"  ! {errore}")
    nome = chiedi_campo("Nome e cognome: ", controlla_nome)
    email = chiedi_campo("Email: ", lambda e: controlla_email(conn, e))
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


def azione_registrazione(conn, _utente=None):
    print("\n--- Registrazione nuovo partecipante ---")
    dati = chiedi_dati_account(conn)
    if dati is None:
        return
    registra_utente(conn, *dati)
    print(f"Registrazione completata. Ora puoi fare il login come '{dati[0]}'.")


TENTATIVI_PRIMA_DELLA_PAUSA = 3
SECONDI_DI_PAUSA = 5


def azione_login(conn, tentativi_falliti):
    """
    Esegue il login e restituisce (utente, tentativi_falliti).
    Dopo 3 tentativi sbagliati di fila il programma fa una pausa
    a ogni nuovo errore, per rendere lenti i tentativi "a caso".
    """
    try:
        utente = login(conn, chiedi_testo("Username: "), chiedi_password())
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


def menu_principale(conn):
    tentativi_falliti = 0
    while True:
        print("\n===== GESTIONE EVENTI MUSICALI =====")
        print("1. Registrazione")
        print("2. Login")
        print("3. Visualizza eventi")
        print("4. Esci")
        scelta = chiedi_intero("Scelta: ", 1, 4)
        if scelta == 1:
            esegui(azione_registrazione, conn, None)
        elif scelta == 2:
            utente, tentativi_falliti = azione_login(conn, tentativi_falliti)
            if utente is not None:
                menu_utente(conn, utente)
        elif scelta == 3:
            stampa_eventi(conn)
        else:
            print("Arrivederci!")
            return


def avvia_programma():
    """Apre il database (creandolo se serve) e mostra il menu principale."""
    conn = connetti()
    if crea_organizzatore_predefinito(conn):
        print("Primo avvio: creato l'account organizzatore 'admin' (password 'admin123').")
        print("Cambia la password dopo il primo accesso.")
    try:
        menu_principale(conn)
    except (KeyboardInterrupt, EOFError):
        print("\nProgramma interrotto.")
    finally:
        conn.close()


# ===========================================================================
# 6. DATI DI ESEMPIO (python gestione_eventi.py --dati-esempio)
# ===========================================================================

def crea_dati_esempio(conn):
    # --- Utenti (le password vengono salvate solo come hash) ---
    crea_organizzatore_predefinito(conn)                      # admin / admin123
    admin = login(conn, "admin", "admin123")
    crea_collaboratore(conn, admin, "staff", "Luca Bianchi", "luca@eventi.local", "staff123")
    registra_utente(conn, "mario", "Mario Rossi", "mario@email.it", "mario123")
    registra_utente(conn, "giulia", "Giulia Verdi", "giulia@email.it", "giulia123")
    mario = login(conn, "mario", "mario123")
    giulia = login(conn, "giulia", "giulia123")

    # --- Eventi ---
    concerto = crea_evento(conn, admin, "Concerto Rock d'Autunno", "concerto",
                           "14/11/2027 21:00", "Teatro Comunale", 30, 25.0,
                           "Serata con band emergenti del territorio.")
    workshop = crea_evento(conn, admin, "Workshop di produzione musicale", "workshop",
                           "20/11/2027 15:00", "Sala prove Musica Viva", 8, 40.0,
                           "Introduzione a DAW, registrazione e mixaggio.")
    dj_set = crea_evento(conn, admin, "DJ set sotto le stelle", "dj_set",
                         "28/11/2027 22:30", "Piazza Maggiore", 100, 0,
                         "Musica elettronica all'aperto, ingresso libero.")

    # --- Prenotazioni ---
    p1 = prenota_concerto(conn, mario, concerto, [5, 6])       # 2 posti numerati
    prenota_concerto(conn, giulia, concerto, [10])
    aggiorna_pagamento(conn, admin, p1, "pagato")
    w1 = prenota_posti(conn, mario, workshop, 1)               # in attesa
    prenota_posti(conn, giulia, workshop, 2)                   # in attesa
    approva_prenotazione(conn, admin, w1)
    prenota_posti(conn, giulia, dj_set, 3)                     # confermata subito


def genera_dati_esempio():
    """Cancella il database attuale (dopo conferma) e lo ricrea con i dati dimostrativi."""
    if os.path.exists(PERCORSO_DB):
        risposta = input("Il database esiste già e verrà cancellato. Continuare? (s/n): ")
        if risposta.strip().lower() not in ("s", "si", "sì"):
            print("Operazione annullata.")
            return
        os.remove(PERCORSO_DB)
    conn = connetti()
    crea_dati_esempio(conn)
    conn.close()
    print(f"Database con dati di esempio creato: {PERCORSO_DB}")
    print("Account: admin/admin123 (organizzatore), staff/staff123 (collaboratore),")
    print("         mario/mario123 e giulia/giulia123 (partecipanti)")


# ===========================================================================
# 7. TEST AUTOMATICI (python gestione_eventi.py --test)
# ===========================================================================

DATA_FUTURA = "15/06/2030 21:00"


class BaseTest(unittest.TestCase):
    """Prepara un database vuoto con un organizzatore, un collaboratore e due partecipanti."""

    def setUp(self):
        self.conn = connetti(":memory:")
        crea_organizzatore_predefinito(self.conn)
        self.org = login(self.conn, "admin", "admin123")
        crea_collaboratore(self.conn, self.org, "staff", "Staff", "staff@test.it", "staff123")
        self.collab = login(self.conn, "staff", "staff123")
        registra_utente(self.conn, "anna", "Anna", "anna@test.it", "anna123")
        registra_utente(self.conn, "bruno", "Bruno", "bruno@test.it", "bruno123")
        self.anna = login(self.conn, "anna", "anna123")
        self.bruno = login(self.conn, "bruno", "bruno123")

    def tearDown(self):
        self.conn.close()

    def nuovo_evento(self, tipo, capienza=5, prezzo=10.0):
        return crea_evento(self.conn, self.org, f"Evento {tipo}", tipo,
                                  DATA_FUTURA, "Bologna", capienza, prezzo)


class TestUtenti(BaseTest):
    """Registrazione, login e password."""

    def errore(self, funzione, *argomenti):
        """Verifica che l'operazione venga rifiutata e restituisce il messaggio di errore."""
        with self.assertRaises(ErroreGestione) as contesto:
            funzione(self.conn, *argomenti)
        return str(contesto.exception)

    # --- password ---
    def test_password_non_salvata_in_chiaro(self):
        riga = self.conn.execute("SELECT * FROM utenti WHERE username = 'anna'").fetchone()
        self.assertNotEqual(riga["password_hash"], "anna123")
        self.assertNotIn("anna123", riga["password_hash"])
        self.assertEqual(len(riga["salt"]), 32)   # salt casuale di 16 byte

    def test_stessa_password_hash_diversi(self):
        """Grazie al salt, due utenti con la stessa password hanno hash diversi."""
        registra_utente(self.conn, "carla", "Carla", "carla@test.it", "anna123")
        h1, h2 = (self.conn.execute("SELECT password_hash FROM utenti WHERE username = ?", (u,))
                  .fetchone()[0] for u in ("anna", "carla"))
        self.assertNotEqual(h1, h2)

    def test_password_deboli_rifiutate(self):
        for pw in ("abc12", "      ", "solelettere", "123456", "nuovo1"):
            self.errore(registra_utente, "nuovo1", "Nuovo", "nuovo@test.it", pw)
        # "nuovo1" è valida come forma, ma è uguale allo username
        self.assertIn("uguale allo username",
                      self.errore(registra_utente, "nuovo1", "Nuovo", "nuovo@test.it", "NUOVO1"))

    # --- registrazione ---
    def test_registrazione_corretta(self):
        uid = registra_utente(self.conn, "  Carla_99 ", "  Carla   Rossi ", " Carla@Test.IT ", "carla123")
        riga = self.conn.execute("SELECT * FROM utenti WHERE id = ?", (uid,)).fetchone()
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
        utente = login(self.conn, "anna", "anna123")
        self.assertEqual((utente["username"], utente["ruolo"]), ("anna", "partecipante"))
        self.assertFalse(utente["password_predefinita"])

    def test_login_ignora_maiuscole_e_spazi_nello_username(self):
        self.assertEqual(login(self.conn, "  ANNA ", "anna123")["username"], "anna")

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
        cambia_password(self.conn, self.org, "admin123", "nuovaPw1")
        self.assertFalse(self.org["password_predefinita"])
        self.errore(login, "admin", "admin123")
        self.assertFalse(login(self.conn, "admin", "nuovaPw1")["password_predefinita"])

    # --- cambio password ---
    def test_cambia_password(self):
        self.errore(cambia_password, self.anna, "sbagliata1", "nuova123")   # vecchia errata
        self.errore(cambia_password, self.anna, "anna123", "anna123")      # uguale alla vecchia
        self.errore(cambia_password, self.anna, "anna123", "corta")        # debole
        cambia_password(self.conn, self.anna, "anna123", "nuova123")
        self.errore(login, "anna", "anna123")
        login(self.conn, "anna", "nuova123")


class TestCreazioneEventi(BaseTest):
    def test_crea_concerto_con_posti_numerati(self):
        eid = self.nuovo_evento("concerto", capienza=20)
        self.assertEqual(posti_disponibili(self.conn, eid), 20)
        self.assertEqual(posti_liberi_concerto(self.conn, eid), list(range(1, 21)))

    def test_dj_set_sempre_gratuito(self):
        eid = self.nuovo_evento("dj_set", prezzo=15)
        self.assertEqual(ottieni_evento(self.conn, eid)["prezzo"], 0)

    def test_solo_organizzatore_crea_eventi(self):
        for utente in (self.anna, self.collab):
            with self.assertRaises(ErroreGestione):
                crea_evento(self.conn, utente, "X", "concerto", DATA_FUTURA, "Y", 10)

    def test_dati_evento_non_validi(self):
        with self.assertRaises(ErroreGestione):
            crea_evento(self.conn, self.org, "X", "concerto", DATA_FUTURA, "Y", 0)
        with self.assertRaises(ErroreGestione):
            crea_evento(self.conn, self.org, "X", "festival", DATA_FUTURA, "Y", 10)
        with self.assertRaises(ErroreGestione):
            crea_evento(self.conn, self.org, "X", "concerto", "31/02/2030 20:00", "Y", 10)
        with self.assertRaises(ErroreGestione):
            crea_evento(self.conn, self.org, "X", "concerto", "01/01/2020 20:00", "Y", 10)


class TestConcerto(BaseTest):
    def setUp(self):
        super().setUp()
        self.eid = self.nuovo_evento("concerto", capienza=5, prezzo=20)

    def test_prenotazione_piu_posti(self):
        pid = prenota_concerto(self.conn, self.anna, self.eid, [1, 2, 3])
        p = ottieni_prenotazione(self.conn, pid)
        self.assertEqual(p["stato"], "confermata")
        self.assertEqual(p["importo"], 60)
        self.assertEqual(p["stato_pagamento"], "non_pagato")
        self.assertEqual(posti_liberi_concerto(self.conn, self.eid), [4, 5])

    def test_stesso_account_prenota_di_nuovo(self):
        prenota_concerto(self.conn, self.anna, self.eid, [1])
        prenota_concerto(self.conn, self.anna, self.eid, [2])
        self.assertEqual(len(elenca_prenotazioni_utente(self.conn, self.anna)), 2)

    def test_posto_gia_occupato(self):
        prenota_concerto(self.conn, self.anna, self.eid, [3])
        with self.assertRaises(ErroreGestione):
            prenota_concerto(self.conn, self.bruno, self.eid, [3])

    def test_tutto_o_niente(self):
        """Se un posto è occupato non deve essere prenotato nemmeno quello libero."""
        prenota_concerto(self.conn, self.anna, self.eid, [3])
        with self.assertRaises(ErroreGestione):
            prenota_concerto(self.conn, self.bruno, self.eid, [2, 3])
        self.assertIn(2, posti_liberi_concerto(self.conn, self.eid))
        self.assertEqual(len(elenca_prenotazioni_utente(self.conn, self.bruno)), 0)

    def test_posto_inesistente(self):
        with self.assertRaises(ErroreGestione):
            prenota_concerto(self.conn, self.anna, self.eid, [6])


class TestDjSet(BaseTest):
    def test_conferma_automatica_e_capienza(self):
        eid = self.nuovo_evento("dj_set", capienza=3)
        pid = prenota_posti(self.conn, self.anna, eid, 2)
        p = ottieni_prenotazione(self.conn, pid)
        self.assertEqual(p["stato"], "confermata")
        self.assertEqual(p["stato_pagamento"], "gratuito")
        with self.assertRaises(ErroreGestione):
            prenota_posti(self.conn, self.bruno, eid, 2)     # ne resta solo 1
        prenota_posti(self.conn, self.bruno, eid, 1)
        self.assertEqual(posti_disponibili(self.conn, eid), 0)


class TestWorkshop(BaseTest):
    def setUp(self):
        super().setUp()
        self.eid = self.nuovo_evento("workshop", capienza=3, prezzo=30)

    def test_richiesta_in_attesa(self):
        pid = prenota_posti(self.conn, self.anna, self.eid, 2)
        self.assertEqual(ottieni_prenotazione(self.conn, pid)["stato"], "in_attesa")
        # finché non è approvata non occupa posti
        self.assertEqual(posti_disponibili(self.conn, self.eid), 3)

    def test_approvazione_non_supera_capienza(self):
        p1 = prenota_posti(self.conn, self.anna, self.eid, 2)
        p2 = prenota_posti(self.conn, self.bruno, self.eid, 2)
        approva_prenotazione(self.conn, self.org, p1)
        with self.assertRaises(ErroreGestione):
            approva_prenotazione(self.conn, self.org, p2)   # 2 + 2 > 3
        self.assertEqual(posti_disponibili(self.conn, self.eid), 1)

    def test_rifiuto(self):
        pid = prenota_posti(self.conn, self.anna, self.eid, 1)
        rifiuta_prenotazione(self.conn, self.org, pid)
        self.assertEqual(ottieni_prenotazione(self.conn, pid)["stato"], "rifiutata")
        with self.assertRaises(ErroreGestione):
            approva_prenotazione(self.conn, self.org, pid)  # non più in attesa

    def test_solo_organizzatore_approva(self):
        pid = prenota_posti(self.conn, self.anna, self.eid, 1)
        for utente in (self.collab, self.anna):
            with self.assertRaises(ErroreGestione):
                approva_prenotazione(self.conn, utente, pid)


class TestAnnullamenti(BaseTest):
    def test_annulla_prenotazione_libera_posti(self):
        eid = self.nuovo_evento("concerto", capienza=5)
        pid = prenota_concerto(self.conn, self.anna, eid, [1, 2])
        annulla_prenotazione(self.conn, self.anna, pid)
        self.assertEqual(ottieni_prenotazione(self.conn, pid)["stato"], "annullata")
        self.assertEqual(posti_disponibili(self.conn, eid), 5)
        prenota_concerto(self.conn, self.bruno, eid, [1])   # il posto è di nuovo prenotabile

    def test_annulla_prenotazione_pagata(self):
        eid = self.nuovo_evento("concerto", capienza=5)
        pid = prenota_concerto(self.conn, self.anna, eid, [1])
        aggiorna_pagamento(self.conn, self.collab, pid, "pagato")
        annulla_prenotazione(self.conn, self.anna, pid)
        self.assertEqual(ottieni_prenotazione(self.conn, pid)["stato_pagamento"], "da_rimborsare")

    def test_partecipante_non_tocca_prenotazioni_altrui(self):
        eid = self.nuovo_evento("dj_set")
        pid = prenota_posti(self.conn, self.anna, eid, 1)
        with self.assertRaises(ErroreGestione):
            annulla_prenotazione(self.conn, self.bruno, pid)
        with self.assertRaises(ErroreGestione):
            elenca_tutte_prenotazioni(self.conn, self.bruno)
        self.assertEqual(len(elenca_prenotazioni_utente(self.conn, self.bruno)), 0)

    def test_doppio_annullamento(self):
        eid = self.nuovo_evento("dj_set")
        pid = prenota_posti(self.conn, self.anna, eid, 1)
        annulla_prenotazione(self.conn, self.anna, pid)
        with self.assertRaises(ErroreGestione):
            annulla_prenotazione(self.conn, self.anna, pid)

    def test_annulla_evento_e_notifiche(self):
        eid = self.nuovo_evento("concerto", capienza=5)
        pid_anna = prenota_concerto(self.conn, self.anna, eid, [1])
        prenota_concerto(self.conn, self.anna, eid, [2])
        prenota_concerto(self.conn, self.bruno, eid, [3])
        aggiorna_pagamento(self.conn, self.org, pid_anna, "pagato")

        inviate = annulla_evento(self.conn, self.org, eid)

        self.assertEqual(sorted(n[0] for n in inviate), ["anna", "bruno"])  # una notifica a testa
        self.assertEqual(len(notifiche_utente(self.conn, self.anna)), 1)
        self.assertEqual(ottieni_evento(self.conn, eid)["stato"], "annullato")
        stati = {p["stato"] for p in elenca_tutte_prenotazioni(self.conn, self.org, eid)}
        self.assertEqual(stati, {"annullata"})
        self.assertEqual(ottieni_prenotazione(self.conn, pid_anna)["stato_pagamento"], "da_rimborsare")
        with self.assertRaises(ErroreGestione):
            prenota_concerto(self.conn, self.bruno, eid, [4])   # evento annullato

    def test_solo_organizzatore_annulla_evento(self):
        eid = self.nuovo_evento("dj_set")
        with self.assertRaises(ErroreGestione):
            annulla_evento(self.conn, self.collab, eid)


class TestPagamenti(BaseTest):
    def test_aggiorna_pagamento(self):
        eid = self.nuovo_evento("workshop", prezzo=30)
        pid = prenota_posti(self.conn, self.anna, eid, 1)
        aggiorna_pagamento(self.conn, self.collab, pid, "pagato")
        self.assertEqual(ottieni_prenotazione(self.conn, pid)["stato_pagamento"], "pagato")

    def test_pagamento_gratuito_non_modificabile_e_permessi(self):
        eid = self.nuovo_evento("dj_set")
        pid = prenota_posti(self.conn, self.anna, eid, 1)
        with self.assertRaises(ErroreGestione):
            aggiorna_pagamento(self.conn, self.org, pid, "pagato")
        with self.assertRaises(ErroreGestione):
            aggiorna_pagamento(self.conn, self.anna, pid, "pagato")


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
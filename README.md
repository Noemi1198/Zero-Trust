# Zero-Trust
**Progetto**: Implementazione di un'architettura Zero Trust con OPA, Envoy e Splunk MLTK
**Autore**: Noemi Percipalle
Questo repository contiene i file sorgente necessari per riprodurre in locale l'ambiente Zero Trust containerizzato descritto nella relazione.

## Prerequisiti
Per eseguire il progetto è necessario avere installato sul proprio sistema:
- **Docker** e **Docker Compose**

## Istruzioni per l'Avvio
1. Clonare il presente repository (o scaricare i file in una cartella locale).
2. Aprire un terminale nella cartella di progetto.
3. Eseguire il comando per l'avvio dei container:
   ```bash
   docker compose up -d
4. Attendere circa 2-3 minuti per l'inizializzazione completa dei servizi (in particolare il database MongoDB e l'interfaccia web di Splunk).

## Configurazione di Splunk (SIEM)
Per visualizzare i log generati in tempo reale dal Policy Decision Point (OPA):
1. Accedere a Splunk all'indirizzo `http://localhost:8000`.
   - **Username:** `admin`
   - **Password:** `<password_splunk_2026>`
2. Navigare in: **Settings > Data Inputs > HTTP Event Collector**.
3. Cliccare su **Global Settings**.
4. Assicurarsi di **togliere la spunta da "Enable SSL"** e salvare (la comunicazione OPA-Splunk in questo PoC avviene in HTTP).

## Riproduzione dei Test (Casi d'Uso)
Per testare il calcolo dinamico del rischio (la soglia di blocco è fissata al valore di Rischio `4.0`), aprire un browser ed effettuare richieste HTTP GET verso la porta `10000` (esposta dal gateway Envoy).

- **Scenario 1 (Accesso Consentito):** `http://127.0.0.1:10000/collection_pubblica`
  *(Rischio calcolato: 1.8 - Inferiore alla soglia. Esito: HTTP 200 OK)*
  
- **Scenario 2 (Blocco Dinamico preventivo):** `http://127.0.0.1:10000/collection_ordini`
  *(Rischio calcolato: 4.5 - Supera la soglia. Esito: HTTP 403 Forbidden)*
  
- **Scenario 3 (Attacco Critico bloccato):** `http://127.0.0.1:10000/collection_pazienti`
  *(Rischio calcolato: 9.0 - Tentativo di esfiltrazione dati sensibili. Esito: HTTP 403 Forbidden)*

## Osservabilità e Actionable Intelligence
Tutti i tentativi di accesso (autorizzati e bloccati) possono essere monitorati in tempo reale su Splunk. 
1. Cliccare su **Search & Reporting**.
2. Eseguire la seguente query SPL per generare l'aggregazione statistica:
   `index="main" | stats count by punteggio_rischio`

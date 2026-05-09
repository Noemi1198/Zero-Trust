package envoy.authz
import rego.v1

# 1. TABELLA IMPATTI
resource_impact := {
    "/collection_pazienti": 10,
    "/collection_ordini": 5,
    "/collection_pubblica": 2
}

default allow := false

# 2. REGOLA ZERO TRUST
allow if {
    path := input.attributes.request.http.path
    ip_utente := input.attributes.source.address.socketAddress.address
    
    impatto := object.get(resource_impact, path, 10)
    probabilita := chiedi_probabilita_a_splunk(ip_utente)
    rischio := impatto * probabilita
    
    # chiamo la funzione di LOG
    # Uso una variabile temporanea '_' per forzare OPA a eseguire l'invio
    _ := invia_log_a_splunk(path, ip_utente, rischio)
    
    # 3. DECISIONE FINALE
    rischio < 4
}

# --- FUNZIONE DI INVIO LOG A SPLUNK ---
invia_log_a_splunk(path, ip, r) := response if {
    response := http.send({
        "method": "POST",
        "url": "http://zta_splunk:8088/services/collector/event",
        "headers": {
            "Authorization": "Splunk 5889bddb-01a4-448b-9aec-1e6ab4fec21f",
            "Content-Type": "application/json"
        },
        "body": {
            "event": {
                "messaggio": "Valutazione ZTA eseguita",
                "risorsa": path,
                "ip_client": ip,
                "punteggio_rischio": r,
                "sistema": "OPA_GATEWAY"
            },
            "sourcetype": "_json"
        }
    })
}

# --- SIMULATORE PROBABILITÀ ---
chiedi_probabilita_a_splunk(ip) := prob if {
    ip == "172.18.0.1" # Il mio IP rilevato dai log
    prob := 0.9        # alto per testare il blocco
} else := prob if {
    ip == "127.0.0.1"
    prob := 0.9
} else := prob if {
    prob := 0.2
}
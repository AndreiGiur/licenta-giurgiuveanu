// Dictionar central de texte explicative pentru butoanele de info (i) din UI.
// Fiecare intrare = ce reprezinta elementul + de ce conteaza, in romana.
// Cheia (topic) e folosita de <InfoTip topic="..." />.
//
// Conventie: adaugarea unei explicatii noi = o singura intrare aici. Cand adaugi
// un <InfoTip topic="x" /> nou intr-o componenta, defineste si "x" mai jos.

export type HelpEntry = { title: string; body: string };

export const HELP: Record<string, HelpEntry> = {
  // ── Scor de expunere ──────────────────────────────────────────────────────
  "exposure-score": {
    title: "Scor de expunere",
    body: "O singura cifra, de la 0 la 100, care rezuma cat de expus este dispozitivul: cu cat e mai mare, cu atat riscul e mai ridicat. Se calculeaza dintr-o suma ponderata a vulnerabilitatilor gasite, cu randamente descrescatoare (e.^(-raw/60)), astfel incat multe probleme minore sa nu sara artificial pana la 100.",
  },
  "findings-count": {
    title: "Vulnerabilitati gasite",
    body: "Numarul total de probleme de securitate detectate la aceasta scanare, dupa aplicarea regulilor. Fiecare problema (finding) contribuie la scorul de expunere in functie de severitate si de ponderea regulii.",
  },

  // ── Sub-scoruri pe categorii (ScoreBreakdownBars) ─────────────────────────
  "cat-critical_risk": {
    title: "Risc critic (40%)",
    body: "Aduna problemele cele mai grave: malware-like, persistenta, conturi compromise, configurari periculoase. Are ponderea cea mai mare (40%) in scorul final fiindca aceste probleme pot duce direct la compromiterea dispozitivului.",
  },
  "cat-network_exposure": {
    title: "Expunere retea (30%)",
    body: "Masoara cat de vizibil si atacabil este dispozitivul prin retea: porturi deschise, servicii expuse, share-uri, conexiuni active. Cu cat suprafata de atac din retea e mai mare, cu atat acest sub-scor creste.",
  },
  "cat-hygiene": {
    title: "Igiena sistemului (20%)",
    body: "Reflecta starea de intretinere de baza: software invechit sau cu vulnerabilitati, firewall dezactivat, sistem la final de viata (EOL), lipsa criptarii. Sunt probleme de configurare care, corectate, reduc semnificativ riscul.",
  },
  "cat-activity": {
    title: "Activitate suspecta (10%)",
    body: "Semnale din jurnalele si procesele recente: incercari esuate de autentificare, escaladari de privilegii, procese sau task-uri neobisnuite. Are ponderea cea mai mica (10%) pentru ca indica indicii, nu neaparat o compromitere confirmata.",
  },

  // ── Monitorizare live ─────────────────────────────────────────────────────
  "device-online": {
    title: "Stare online / offline",
    body: "Arata daca agentul de pe dispozitiv comunica acum cu platforma. Agentul trimite un semnal (heartbeat) la fiecare 10 secunde; daca ultimul semnal e mai vechi de 30 de secunde, dispozitivul e considerat offline si nu poate fi scanat in acest moment.",
  },
  "connection-topology": {
    title: "Diagrama conexiunii",
    body: "Ilustreaza traseul datelor: Agent (PC-ul tau) -> Backend (API) -> Platforma (interfata). Toate conexiunile pornesc dinspre agent (HTTPS spre exterior), deci dispozitivul nu expune niciun port. Pachetele animate apar cand agentul e online sau ruleaza o scanare.",
  },
  "network-traffic": {
    title: "Trafic de retea (live)",
    body: "Graficul arata in timp real cati KB/s ies (upload) si intra (download) pe dispozitiv, pe ultimele ~10 minute, plus numarul de conexiuni active. Datele provin de la nivelul sistemului de operare (psutil) si reflecta tot traficul masinii, util pentru a observa activitate neobisnuita.",
  },

  // ── Tipuri de scanare ─────────────────────────────────────────────────────
  "scan-type": {
    title: "Tip de scanare",
    body: "Alege profunzimea analizei: Standard (rapida, ~45-90s, verificari de baza), Advanced (~3-8 min, procese, servicii, conexiuni, nmap moderat) si Deep (~10-20 min, persistenta, forensics, nmap agresiv cu detectie CVE). Cu cat profilul e mai adanc, cu atat mai multe reguli se aplica si mai mult dureaza.",
  },
  "scans-list": {
    title: "Istoricul scanarilor",
    body: "Lista scanarilor efectuate pe acest dispozitiv, cele mai recente sus. Fiecare intrare arata numarul scanarii, scorul de expunere obtinut si data. Selecteaza o scanare pentru a-i vedea vulnerabilitatile si detaliile.",
  },

  // ── Findings (vulnerabilitati) ────────────────────────────────────────────
  "findings": {
    title: "Vulnerabilitati (findings)",
    body: "Lista problemelor de securitate gasite de motorul de reguli pe baza datelor colectate. Fiecare finding are un titlu, o severitate si o recomandare de remediere; in pagina de detalii vezi si dovezile concrete care au declansat regula.",
  },
  "severity": {
    title: "Severitate",
    body: "Cat de grava este problema: critical si high cer atentie imediata, medium e de rezolvat in timp util, low si info sunt mai degraba observatii. Severitatea influenteaza direct cat cantareste problema in scorul de expunere.",
  },
  "recommendation": {
    title: "Recomandare",
    body: "Pasul concret prin care poti remedia sau reduce problema. Recomandarile sunt formulate pentru a fi aplicabile direct de catre utilizator, fara cunostinte avansate de securitate.",
  },
  "finding-evidence": {
    title: "Dovezi",
    body: "Datele concrete colectate de pe dispozitiv care au declansat regula: porturi, nume de procese, chei de registru, intrari din jurnal etc. Servesc la verificarea problemei si la intelegerea exacta a ceea ce a fost detectat.",
  },
  "rule-id": {
    title: "Identificator de regula",
    body: "Codul unic al regulii care a generat acest finding (de ex. NET-OPEN-PORTS-1). Ajuta la urmarirea consecventa a aceleiasi probleme intre scanari si in documentatie.",
  },
  "compliance": {
    title: "Conformitate (CIS / NIST)",
    body: "Mapeaza problema la controale din standarde recunoscute: CIS Controls v8 si NIST Cybersecurity Framework 2.0. Arata ca detectia nu e arbitrara, ci corespunde unor bune practici de securitate acceptate la nivel international.",
  },

  // ── Categorii in pagina de scan ───────────────────────────────────────────
  "category-nav": {
    title: "Categorii de vulnerabilitati",
    body: "Vulnerabilitatile sunt grupate pe domenii (Retea, Sistem & OS, Software, Procese & Servicii, Persistenta, Event Log & Forensics). Numarul de langa fiecare categorie arata cate probleme contine, iar culoarea indica severitatea cea mai ridicata din grup.",
  },

  // ── nmap ──────────────────────────────────────────────────────────────────
  "nmap": {
    title: "Scanare de retea (nmap)",
    body: "In profilul deep, platforma foloseste nmap pentru a descoperi celelalte dispozitive din reteaua locala, serviciile lor si eventuale vulnerabilitati. Ofera o perspectiva dincolo de dispozitivul propriu, asupra contextului de retea in care acesta functioneaza.",
  },
  "nmap-host": {
    title: "Dispozitiv descoperit",
    body: "Un host gasit in reteaua locala, identificat prin adresa IP (si hostname, daca e disponibil). Pentru fiecare host se afiseaza rolul probabil in retea, porturile deschise si eventualele probleme detectate.",
  },
  "nmap-role": {
    title: "Rol in topologie",
    body: "Rolul probabil al dispozitivului in retea (gateway, DNS, file server, statie de lucru), dedus din porturile si serviciile observate. Ajuta sa intelegi importanta fiecarui host: un gateway sau un server expus conteaza mai mult decat o statie obisnuita.",
  },
  "nmap-risk": {
    title: "Risc host (0-100)",
    body: "Un scor de risc atribuit dispozitivului de catre scriptul de analiza, pe baza serviciilor expuse si a vulnerabilitatilor gasite. Cu cat e mai mare, cu atat host-ul respectiv reprezinta un punct mai sensibil in retea.",
  },
  "nmap-os": {
    title: "Sistem de operare estimat",
    body: "O estimare a sistemului de operare al host-ului, dedusa din amprenta retelei (OS fingerprinting). Este orientativa: ajuta la evaluarea riscului, dar nu e o identificare garantata.",
  },
  "nmap-ports": {
    title: "Porturi deschise",
    body: "Porturile pe care host-ul accepta conexiuni, cu serviciul si versiunea detectate (de ex. 22/tcp ssh OpenSSH 9.6). Porturile deschise sunt usi catre dispozitiv: fiecare serviciu expus, mai ales daca e invechit, poate fi o cale de atac.",
  },
  "nmap-findings": {
    title: "Probleme per host",
    body: "Vulnerabilitatile gasite pe acel dispozitiv din retea (de ex. servicii cu CVE cunoscute), colorate dupa severitate. Provin din scripturile NSE rulate de nmap in profilul deep.",
  },
  "nmap-lua-errors": {
    title: "Avertismente NSE",
    body: "Mesaje generate de scripturile Lua (NSE) ale nmap in timpul scanarii. De obicei sunt avertismente minore (timeout-uri, servicii care nu raspund) si nu inseamna ca scanarea a esuat.",
  },

  // ── Diff intre scanari ────────────────────────────────────────────────────
  "diff-delta": {
    title: "Variatia scorului",
    body: "Diferenta de scor fata de scanarea anterioara. O scadere (verde) inseamna imbunatatire, o crestere (rosu) inseamna regresie. Te ajuta sa vezi imediat daca dispozitivul a devenit mai sigur sau mai expus de la ultima verificare.",
  },
  "diff-added": {
    title: "Vulnerabilitati adaugate",
    body: "Probleme care apar acum, dar nu existau la scanarea anterioara. Sunt cele pe care merita sa le verifici primele, fiind aparute intre cele doua scanari.",
  },
  "diff-fixed": {
    title: "Vulnerabilitati rezolvate",
    body: "Probleme prezente la scanarea anterioara care nu mai apar acum. Confirma ca remedierile aplicate au avut efect.",
  },
  "diff-unchanged": {
    title: "Vulnerabilitati nemodificate",
    body: "Probleme prezente in ambele scanari, ramase neschimbate. De obicei sunt cele inca neabordate sau pe care le-ai acceptat ca risc.",
  },

  // ── Trend ─────────────────────────────────────────────────────────────────
  "score-trend": {
    title: "Evolutia scorului",
    body: "Graficul arata cum a variat scorul de expunere al dispozitivului in timp. O tendinta descendenta inseamna ca securitatea s-a imbunatatit; benzile colorate de fundal marcheaza pragurile de severitate.",
  },

  // ── Profil: statistici personale ──────────────────────────────────────────
  "stat-device-count": {
    title: "Numar de dispozitive",
    body: "Cate dispozitive ai inrolat in contul tau. Fiecare dispozitiv are propriul agent si propriul istoric de scanari.",
  },
  "stat-scan-count": {
    title: "Total scanari",
    body: "Numarul total de scanari efectuate pe toate dispozitivele tale. Un istoric mai bogat permite o analiza de tendinta mai relevanta.",
  },
  "stat-avg-score": {
    title: "Scor mediu",
    body: "Media scorurilor de expunere de pe ultimele tale scanari. Ofera o imagine de ansamblu asupra starii generale de securitate a dispozitivelor tale.",
  },
  "stat-last-scan": {
    title: "Ultima scanare",
    body: "Cand a avut loc cea mai recenta scanare si ce scor a obtinut. Scanarile regulate mentin evaluarea actualizata fata de schimbarile din sistem.",
  },
  "pref-scan-type": {
    title: "Tip de scanare implicit",
    body: "Profilul de scanare selectat automat cand pornesti o scanare noua din interfata. Il poti schimba oricand inainte de fiecare scanare.",
  },
  "sessions": {
    title: "Sesiuni active",
    body: "Dispozitivele si browserele de pe care esti autentificat acum in cont. Daca observi o sesiune necunoscuta, o poti revoca pentru a o deconecta imediat. Sesiunile expira automat dupa 24 de ore.",
  },
  "session-current": {
    title: "Sesiunea curenta",
    body: "Marcheaza sesiunea de pe care vizualizezi acum platforma. Aceasta nu poate fi revocata din lista, ca sa nu te deconectezi din greseala chiar pe tine.",
  },

  // ── Profil: statistici platforma (doar admin) ─────────────────────────────
  "platform-total-users": {
    title: "Total utilizatori",
    body: "Numarul total de conturi inregistrate pe platforma. Indicator administrativ, vizibil doar pentru administratori.",
  },
  "platform-devices-online": {
    title: "Dispozitive online",
    body: "Cate dispozitive comunica acum cu platforma, din totalul inrolat. Reflecta cati agenti sunt activi in acest moment.",
  },
  "platform-scans-24h": {
    title: "Scanari in ultimele 24h",
    body: "Numarul de scanari efectuate pe intreaga platforma in ultima zi. Indicator al gradului de utilizare recent.",
  },
  "platform-avg-score": {
    title: "Scor mediu pe platforma",
    body: "Media scorurilor de expunere de pe toate dispozitivele platformei. Ofera o imagine globala asupra starii de securitate a parcului de dispozitive.",
  },

  // ── Admin: coloane tabele ─────────────────────────────────────────────────
  "admin-user-role": {
    title: "Rol",
    body: "Nivelul de acces al contului: user (acces doar la propriile dispozitive) sau admin (acces la administrarea platformei). Il poti schimba din acest selector.",
  },
  "admin-user-provider": {
    title: "Metoda de autentificare",
    body: "Cum se conecteaza utilizatorul: email & parola, Google, sau ambele (cont legat automat dupa email). Util pentru a intelege cum isi gestioneaza accesul.",
  },
  "admin-user-devices": {
    title: "Dispozitive",
    body: "Cate dispozitive a inrolat utilizatorul. La stergerea contului, toate dispozitivele lui sunt sterse odata cu el.",
  },
  "admin-device-status": {
    title: "Stare dispozitiv",
    body: "Daca agentul dispozitivului comunica acum cu platforma (online) sau nu (offline). Se bazeaza pe ultimul heartbeat primit.",
  },
  "admin-scan-type": {
    title: "Tip scanare",
    body: "Profilul cu care a fost rulata scanarea: standard, advanced sau deep. Determina ce date au fost colectate si cate reguli s-au aplicat.",
  },
  "admin-scan-score": {
    title: "Scor de expunere",
    body: "Scorul de expunere (0-100) rezultat la acea scanare. Cu cat e mai mare, cu atat dispozitivul era mai expus la momentul scanarii.",
  },
};

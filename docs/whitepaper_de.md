# Vertragliche Agenten: Ein sicheres Framework für Agenten mit vertragsbasiertem Tool‑Zugriff, vermittelten Geheimnissen, WASM‑Skills und Multi‑Agent‑Orchestrierung

## Inhaltsübersicht

1. Einleitung
2. Problemanalyse und Motivation
3. Designziele und Anforderungen
3.1 Safe Use für nicht‑technische Nutzer
4. Bedrohungsmodell
5. Gesamtarchitektur
6. Verträge: einheitliche Autorisierungsobjekte
7. Policy‑Engine: Capability Model, Budgets und Data Guards
7.1 Structured Outputs (Schema‑First LLM I/O)
8. Vermittelte Geheimnisse: Zero‑Token‑Exposure
8.1 Secure Secret Provisioning (Control UI Flow)
9. Runner: Ausführungsbereiche, Egress‑Kontrolle und Output‑Sanitizer
10. Skills und Plugin‑Modell
11. Zeitgesteuerte und ereignisgesteuerte Automatisierung
12. Multi‑Agent‑Unterstützung und Orchestrierung
13. Artifact‑basierte Ausgaben
14. Speicherbereiche und Promotion
15. Audit, Observability und Forensics
16. Referenz‑Workflows
17. Pseudocode‑Beispiele
18. Deployment und Monorepo‑Struktur
19. Glossar
20. Ausblick und Roadmap
21. Schlussbemerkung

## 1 Einleitung

Künstliche Intelligenzen, die als persönliche Assistenten, Companion‑Agenten oder Geschäftsagenten Aufgaben autonom ausführen, gewinnen rasant an Popularität. Projekte wie **OpenClaw** (früher *ClawdBot* oder *MoltBot*) zeigen, wie leistungsfähig solche Agenten sein können. Sie verbinden sich gleichzeitig mit Messengern, E‑Mail‑Systemen, Cloud‑Diensten, Git‑Repositorys und Betriebssystemwerkzeugen. Dieser Komfort geht jedoch mit gravierenden Sicherheitsrisiken einher. Untersuchungen zeigen, dass OpenClaw umfangreiche Berechtigungen benötigt – Dateisystemzugriff, Bash‑Ausführungsrechte, API‑Schlüssel und Netzwerkzugriffe – wodurch die Komplexität und damit die Angriffsfläche steigt([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). Nutzer installieren den Assistenten häufig mit weitreichendem Zugang zu E‑Mails, Dateien, Kalendern und API‑Schlüsseln ohne geeignete Isolation([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). In vielen Fällen wird die lokale Web‑Schnittstelle öffentlich erreichbar gemacht oder ohne Authentifizierung betrieben, so dass Angreifer den Agenten über das Netzwerk steuern können([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)).  

OpenClaw betreibt typischerweise einen lokalen Gateway‑Prozess mit Control UI, lädt Skills im selben Prozess und speichert Credentials lokal. Damit teilen UI, Skill‑Code und Geheimnisse denselben Vertrauensbereich, was bei Kompromittierung zu vollständigem Zugriff führen kann.

Aus der Analyse ergeben sich wiederkehrende Fehlerklassen: Prompt‑Injection zur Befehlsausführung, überbreite Integrationen mit langlebigen Tokens, Supply‑Chain‑Risiken im Skill‑Ökosystem und Fehlkonfigurationen der Web‑UI.

Im Februar 2026 wurde zudem eine schwerwiegende Schwachstelle (CVE‑2026‑25253) gemeldet, die einen *one‑click RCE‑Angriff* ermöglichte. Dabei vertraute die Control UI der Abfrageparameter zu stark und übermittelte beim Verbindungsaufbau automatisch ein Gateway‑Token an eine beliebige Web‑Site; ein Klick auf einen präparierten Link reichte aus, um das Token an einen Angreifer zu senden. Der Angreifer konnte damit die Konfiguration ändern und beliebige Befehle auf dem Host ausführen([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Die Ursache lag in fehlender Validierung des `WebSocket`‑Origins; so konnte eine bösartige Seite das Token abfangen, sich gegenüber dem Gateway authentifizieren und die Sandbox umgehen([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Dieser Vorfall zeigt, dass existierende Sicherheitsfunktionen wie Sandboxen und Genehmigungsmechanismen die Gefahr nicht ausreichend eingrenzen([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).  

Ein weiteres Problem ist das noch unzureichend geprüfte Ökosystem von „Skills“. Community‑Plugins können unbemerkt schädlichen Code oder Malware enthalten und weitreichende Berechtigungen anfordern([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). Sicherheitsforscher fanden Dutzende bösartige Skills auf dem inoffiziellen Marktplatz ClawdbHub([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)).  

Dieses Whitepaper fasst die Diskussionen aus unserem Chat zusammen und beschreibt ein neues Framework, das diese Probleme adressiert. Es stellt **vertragliche Agenten** vor – eine Architektur, die Privilegien strikt trennt, jede Werkzeugnutzung über explizite Verträge genehmigt und Geheimnisse niemals direkt an das Sprachmodell weitergibt. Jede Designentscheidung wird durch das zugrunde liegende Problem motiviert, deren Auswirkungen erläutert und ein Lösungsansatz präsentiert.

## 2 Problemanalyse und Motivation

### 2.1 Übermäßige Berechtigungen und fehlende Isolation

**Problem:** OpenClaw fungiert als lokaler Gateway‑Prozess mit Web‑UI. Zur Nutzung verbindet der Agent Dateien, E‑Mails, Kalender, Chat‑Kanäle und Cloud‑APIs. Um diese Funktionen „einfach zum Laufen zu bringen“, vergeben Nutzer dem Agenten Lese‑/Schreibrechte auf das Dateisystem, Shell‑Zugriff, langfristige API‑Tokens und Netzberechtigungen([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). In vielen Installationen läuft die Web‑Schnittstelle auf allen Interfaces und ohne Authentifizierung([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). Credentials werden lokal gespeichert, und Skills laufen im Gateway‑Prozess – Tools, UI und Geheimnisse teilen damit denselben Prozessraum.

**Implikation:** Der Agent wird zu einem „Superuser“, der ohne weitere Einschränkungen E‑Mails lesen, Dateien löschen, Code ausführen oder Cloud‑Konten verändern kann. Eine einzige Fehlkonfiguration oder Kompromittierung (z. B. durch RCE) verschafft Angreifern Zugriff auf alle Systeme des Nutzers. Da Agenten lernbasierte Modelle nutzen, sind sie zudem anfällig für *Prompt‑Injection*. Die Ausführung von Shell‑Befehlen und Dateizugriff in derselben Sandbox erhöht die Wahrscheinlichkeit, dass bösartige Eingaben zu unerwarteten Aktionen führen.

**Lösungsansatz:** Unser Framework führt ein **Capability Model** ein, das alle Aktionen des Agenten in fein definierte Capabilities zerlegt. Jede Capability ist mit konkreten Parametern (z. B. erlaubte Pfade, erlaubte Empfänger) verbunden und kann nur innerhalb eines genehmigten **Vertrags** ausgeführt werden. Standardmäßig ist jede Capability deaktiviert; nur explizit freigegebene Aktionen werden ausgeführt. Das Gateway bleibt weiterhin das zentrale Einfallstor, aber ohne Ausführungsrechte – es leitet Anfragen an die Engine weiter und holt vor riskanten Aktionen die Bestätigung über eine vertrauenswürdige UI ein.

### 2.2 Token‑Leckage und Fehlkonfiguration der Control UI

**Problem:** Die erwähnte Schwachstelle (CVE‑2026‑25253) demonstriert, dass Tokens an das Web geleakt werden können. Die Control UI leitete das `gatewayUrl` aus der URL ohne Validierung an den WebSocket‑Verbindungsaufbau weiter; dadurch konnte ein Angreifer das Gateway‑Token abfangen([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Weitere Untersuchungen zeigten, dass durch Cross‑Site‑WebSocket‑Hijacking selbst Gateways, die nur auf `localhost` hörten, kompromittiert werden konnten([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Zusätzlich konnten Angreifer Konfigurationsparameter wie `exec.approvals.set` oder `tools.exec.host` ändern und so die Sandbox aushebeln([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).

**Implikation:** Wenn ein Angreifer das Gateway‑Token stiehlt, erhält er administrative Kontrolle über den Agenten. Er kann Sicherheitsmechanismen ausschalten, die Ausführung vom Container auf den Host umstellen und willkürliche Befehle ausführen. Bestehende LLM‑Sandboxen und Genehmigungssysteme schützen nicht vor dieser Klasse von Angriffen([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Der Vorfall belegt, dass eine einfache Bindung an `localhost` nicht ausreicht, wenn der Browser des Nutzers als Brücke missbraucht werden kann([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).

**Lösungsansatz:** Unser Framework sieht vor, dass **Geheimnisse niemals in die Modell‑Prompts gelangen** und im Browser nicht persistiert werden. Tokens und Schlüssel werden ausschließlich vom **Secrets‑Broker** verwaltet. Wenn ein Runner eine API aufrufen muss, erhält er nur einen *opaquen Handle* vom Broker. Dieser Handle ist auf ein einzelnes Werkzeug, konkrete Parameter, einen sehr kurzen Zeitraum und einen bestimmten Runner begrenzt. Selbst wenn ein Angreifer den Handle abfangen würde, könnte er damit keine externen Dienste missbrauchen. Ferner wird die Control UI so gestaltet, dass sie keine direkten Token im Browser speichert; Verbindungen werden durch Pairing und mTLS abgesichert und Anfragen immer serverseitig signiert. Pairing ist **kurzlebig, einmalig und gerätegebunden** (Challenge wird mit dem Geräteschlüssel signiert), **Origin/CSRF‑gebunden** und **nutzt keine URL‑Parameter**; die finale Bindung erfordert eine explizite Bestätigung am Gerät.

### 2.3 Unsichere Skill‑Ökosysteme

**Problem:** Die Community von OpenClaw teilt Skills ohne strenge Prüfung. Viele dieser Pakete sind ungewartet oder enthalten Malware. Sicherheitsforscher wiesen nach, dass unzählige Skills uneingeschränkt Berechtigungen fordern, schädliche Nutzlasten enthalten oder sensible Daten exfiltrieren([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). Die Mehrfachumbenennung des Projekts erleichtert Phishing und das Hochladen gefälschter Erweiterungen([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). Ein Beispiel ist ein VS‑Code‑Plugin namens „ClawdBot Agent“, das sich als offizielles Werkzeug ausgab und Trojaner enthielt([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)).

**Implikation:** Das Vertrauen in ein umfangreiches, weitgehend unkontrolliertes Skill‑Ökosystem führt dazu, dass Angreifer bösartige Erweiterungen verbreiten. Installiert der Nutzer eine solche Erweiterung, erhält der Angreifer Zugriff auf die gleichen Berechtigungen wie der Agent: Dateien lesen/schreiben, E‑Mails versenden oder Shell‑Befehle ausführen. Bisherige Mechanismen können den Umfang der Berechtigungen kaum einschränken, da Skills im selben Prozess wie der Agent laufen.

**Lösungsansatz:** In unserer Architektur sind Skills **WASM‑Module**, die streng isoliert ausgeführt werden. Jedes Skill‑Paket enthält eine signierte Manifestdatei mit deklarativen Beschreibungen: ID, Version, Herausgeber, erforderliche Capabilities, Schema der Werkzeuge und erlaubte Netzwerkziele. Bei der Installation wird die Signatur **und die Publisher‑Trust‑Chain** (Root in einer Allowlist oder auditierter Schlüssel) verifiziert und die Eintragung in einem Transparenz‑Log (lokal/privat standardmäßig) geprüft; gesperrte Publisher werden blockiert. Das Skill muss durch den Nutzer explizit aktiviert werden. Tools innerhalb des Skills haben nur Zugriff auf die vom Policy‑Engine genehmigten Ressourcen. Wenn native Funktionalität nötig ist (z. B. Hardware‑Zugriff), muss ein zweistufiges Plugin genutzt werden: Das WASM‑Modul orchestriert die Logik; eine separate **Native Companion Service** führt die Aktion in einer isolierten Umgebung aus. Dieser Dienst ist über mTLS authentifiziert, und jede Anfrage ist an einen genehmigten Vertrag und eine Entscheidung gebunden.  

### 2.4 Unbeaufsichtigte Automatisierung

**Problem:** Nutzer möchten Aufgaben periodisch oder ereignisgesteuert ausführen (z. B. „Starte jeden Abend ein Backup“, „Erstelle täglich einen Statusbericht“). Bei OpenClaw können Agenten ohne weitere Freigabe zeitgesteuerte oder reaktive Aktionen ausführen. Die breite Berechtigungsvergabe und fehlende Rollenabgrenzung führen dazu, dass diese Jobs im Schlaf unkontrolliert Änderungen durchführen oder externe Nachrichten verschicken können.

**Implikation:** Unbeaufsichtigte Agenten erhöhen das Risiko massiven Schadens. Prompt‑Injektionen in E‑Mails oder Logs können automatisierte Jobs manipulieren. Fehlerhafte LLM‑Antworten können Daten löschen oder vertrauliche Infos an Dritte senden. Eine einzige Fehlfunktion in einem Cron‑Job kann hunderte E‑Mails verschicken oder Produktionssysteme ändern.

**Lösungsansatz:** Das Framework führt **Job‑Principals** ein: Jeder geplante Job wird als eigener Principal mit spezifischen Rechten behandelt. Ein Job darf nur dann unsupervised laufen, wenn er auf Grundlage eines genehmigten **wiederverwendbaren Vertrags** erstellt wurde. Dieser Vertrag definiert zulässige Werkzeuge, Parametergrenzen, Budgets (Laufzeit, Anzahl Tool‑Aufrufe, Datenvolumen), Ziel‑Alarmlisten und Datenverarbeitungsregeln. Wenn ein Job von diesem Vertrag abweicht oder die Version eines Skills, der Policy oder der Werkzeuge sich ändert, pausiert das System den Job automatisch und verlangt eine erneute Genehmigung. Zusätzlich besitzen unbeaufsichtigte Jobs strengere Standardrichtlinien: Sie dürfen keine „High‑Risk“-Tools (z. B. Shell‑Ausführung) nutzen und müssen Out‑Of‑Band genehmigt werden, bevor sie externe Nachrichten versenden.

### 2.5 Verarbeitung großer und unvorhersehbarer Ausgaben

**Problem:** Viele Aufgaben, wie automatisierte Code‑Generierung oder Berichtserstellung, produzieren umfangreiche Ausgaben. LLM‑basierte Systeme, die diese Daten direkt in den Chat‑Kontext einbetten, stossen an Kontext‑Limits oder riskieren, dass sensible Informationen ungewollt im Prompt landen und somit weitergeleitet werden.

**Implikation:** Unbegrenzte Ausgaben können zu hohen Kosten (Tokenverbrauch), unlesbaren Chats und Datenlecks führen. In bestehendem Agenten‑Design werden Code‑Diffs, Logs oder Dokumente oft ungekürzt in den Gesprächsfluss gepusht.  

**Lösungsansatz:** Unser Framework führt **Artifacts** als primäre Form grosser Ausgaben ein. Werkzeuge, die große Datenmengen erzeugen (z. B. Code‑Patches, Reports, Datenbanken), speichern diese als Datei in einem Artifact‑Store. Die Engine liefert nur eine Zusammenfassung, eine Vorschau (Auszug) und einen Verweis auf das Artifact zurück. Artifacts sind at rest verschlüsselt, Zugriff ist pro Principal gescoped und Retention/TTL wird erzwungen. Artifacts sind **standardmäßig untrusted**: jedes Artifact trägt Provenienz und einen Content‑Hash, wird beim Schreiben und Lesen gescannt und darf nur mit expliziter Allowlist oder Genehmigung re‑ingestiert werden. Verträge legen Grenzwerte für Artifact‑Größe, Anzahl geänderter Dateien, erlaubte Dateitypen und Speicherdauer fest. Für Code‑Aufgaben empfehlen wir Workflow‑Schritte: erst planen (Welche Dateien werden verändert?), dann Patch generieren, testen, überprüfen lassen und schlussendlich anwenden – letzteres unter neuer Genehmigung. So bleibt die Konversation schlank und die Verarbeitung kontrollierbar.


## 3 Designziele und Anforderungen


### 3.1 Safe Use für nicht‑technische Nutzer

Dieses Framework ist so ausgelegt, dass auch nicht‑technische Nutzer sicher arbeiten können. Dazu gehören strikte Defaults, verständliche Genehmigungen und klare Schutzmechanismen.

**Safe Setup Checklist:**

- Gateway auf `localhost` lassen oder über ein privates VPN/Zero‑Trust‑Netz (z. B. Tailnet) zugänglich machen; keine öffentlichen Ports freigeben.
- Secrets ausschließlich über den Control UI‑Flow erfassen.
- Contracts nur mit minimalen Capabilities freigeben.
- Read‑only Skills bevorzugen, bis das System verstanden ist.
- Scheduled Jobs mit engen Budgets betreiben.

**Häufige Fehler und Schutzmechanismen:**

- Public UI Exposure: standardmäßig blockiert, Warnungen bei Risk‑Konfiguration.
- Over‑broad Approvals: Contracts zeigen klare Summary und Risk‑Label.
- Secrets im Chat: Best‑Effort DLP/Regex‑Erkennung blockiert und warnt bei Secret‑Pattern; das ist kein Primärschutz—Secrets nur über die Control UI erfassen.
- Untrusted Skills: Unsigned Skills lösen Warnungen und zusätzliche Bestätigungen aus.
- Unsafes Automation: High‑Risk Tools sind für Jobs standardmäßig deaktiviert.

**Default Safe Profiles:**

- Personal assistant (safe): Read‑only Tools, keine externen Sends.
- Ops digest (safe): Bounded Email Search und Single‑Channel Posting.
- Code review (safe): Artifact‑only Outputs, keine Repo‑Writes.

**Secret Rule:** Niemals Secrets im Chat posten. Verwende den Control UI‑Flow, damit das LLM keine Tokens sieht.

**Safe Mode:** Aktiviert Read‑only Defaults, blockiert External Sends und erzwingt Step‑up Approval für Writes.


Die nachstehenden Ziele leiten alle Designentscheidungen:

1. **Token‑Null‑Exposition (G1).** Das LLM darf niemals Zugriff auf API‑Schlüssel, Tokens oder andere Geheimnisse erhalten. Geheimnisse verbleiben im Secrets‑Broker und werden nur als nicht wiederverwendbare Handles an Runner herausgegeben. So wird verhindert, dass ein kompromittiertes LLM Tokens exfiltriert oder in Prompts weiterleitet.([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html))
2. **Standardmäßiges Verweigern (G2).** Es sind keine Aktionen ohne explizite Genehmigung erlaubt. Alle Capabilities sind zunächst deaktiviert; Nutzer müssen sie pro Agent, Workspace oder Job explizit freischalten.
3. **Vertragsbasierte Ausführung (G3).** Jedes Tool wird ausschließlich im Rahmen eines genehmigten Vertrags ausgeführt – entweder einmalig (One‑Shot) oder wiederverwendbar (für Jobs). Verträge definieren Parametergrenzen, Budgets, Datenhandhabung und Gültigkeitsdauer.
4. **Isolierte Ausführung (G4).** Die Agenten‑Engine darf keine Tools direkt ausführen. Werkzeuge werden in **Runnern** (WASM‑Sandboxen oder isolierten Containern) ausgeführt. Native Funktionen sind nur über Companion‑Services möglich, die per mTLS authentifiziert sind.
5. **Vertrauenswürdige Bestätigungen (G5).** Risikenbehaftete Aktionen (z. B. externe Sendungen, Dateischreibzugriffe) erfordern eine Bestätigung über die Control UI (paart mit Endgerät). Genehmigungen über Chat‑Nachrichten werden nicht akzeptiert.
6. **Auditierbarkeit (G6).** Alle Entscheidungen (Allow, Deny, Approval), alle Tool‑Aufrufe, Artifact‑Erstellungen und ausgehenden Aktionen werden lückenlos in einer unveränderlichen Audit‑Log aufgezeichnet.
7. **Structured Outputs (G7).** Alle LLM‑Antworten, die in Steuerungslogik einfließen, müssen schema‑konform sein (z. B. JSON‑Schema). Nicht‑konforme Antworten werden verworfen oder erneut angefordert.

Zusätzlich definieren wir ein **Standard‑Hardening‑Profil**, das für neue Installationen aktiv ist:

- Gateway nur über `localhost` und Pairing erreichbar, keine öffentlichen Interfaces ohne explizite Policy.
- Striktes Deny‑by‑Default für Capabilities, Netz‑Egress ausschließlich per Allowlist.
- Keine Token oder Secrets im Browser oder im LLM‑Kontext.
- High‑Risk‑Tools in Jobs standardmäßig deaktiviert; Step‑up‑Approval über die Control UI.
- Output‑Redaction und Artifact‑Limits aktiv, um PII und Secrets zu schützen.


## 4 Bedrohungsmodell

Das Framework schützt vor folgenden Angriffsvektoren:

- **Prompt‑Injection und bösartige Nutzereingaben.** Untrusted Input, egal ob aus Chat, Web oder E‑Mails, darf nicht ungefiltert zu hochprivilegierten Aktionen führen.  
- **Angriffe auf die UI (Cross‑Site‑Hijacking).** Tokens dürfen nicht im Browser gespeichert werden; mTLS und strikte Header‑Validierung sind Pflicht, um RCEs wie CVE‑2026‑25253 zu verhindern([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).  
- **Malware in Skills/Plugins.** Nur signierte WASM‑Skills dürfen installiert werden; native Code läuft isoliert.  
- **Offene Ports und Fehlkonfiguration.** Das Gateway ist standardmäßig nur über `localhost` erreichbar. Ausnahmen erfordern explizite Netzwerkrichtlinien.  
- **Exfiltration über Tools oder Artifacts.** Output‑Filter verhindern, dass Secrets, PII oder Tokens aus dem System ausgeleitet werden.  

Nicht adressiert werden kompromittierte Hosts oder Hardware‑Angriffe. Wer einen Root‑Zugriff auf das Betriebssystem hat, kann das Framework umgehen. Der Fokus liegt auf Software‑Sicherheitsgarantien.


## 5 Gesamtarchitektur

Die Architektur ist modular aufgebaut (siehe Abbildung 1). Hauptkomponenten:

1. **Gateway:** Zentrale Schnittstelle für alle Eingaben (Messenger, E‑Mail, UI). Es verwaltet Sitzungen, Pairing und zeigt Genehmigungsanfragen an. Externe Kanäle laufen über kontrollierte Relays; öffentliche Exponierung erfordert explizite Netz‑Policies. Das Gateway hat keine Ausführungsberechtigung; es leitet lediglich Nachrichten und Entscheidungsergebnisse weiter.
2. **Engine:** Füttert das LLM, extrahiert Absichten, generiert Pläne und schlägt Tool‑Aufrufe vor. Sie hat keine Möglichkeit, selbst Tools auszuführen oder auf Secrets zuzugreifen.
3. **Policy‑Engine:** Bewertet vorgeschlagene Tool‑Aufrufe anhand von Verträgen, Capabilities und Budgets. Ergebnis ist „Allow“, „Deny“ oder „Genehmigung erforderlich“. Data Guards prüfen In‑ und Out‑Bound‑Daten auf sensible Inhalte.
4. **Runner:** Ausführungsumgebung für Tools. Jede Capability läuft in einer isolierten Sandbox (WASM oder Container). Runner nutzen den Secrets‑Broker, um API‑Aufrufe mit kurzen Handles durchzuführen.
5. **Skill‑Registry:** Repository für signierte WASM‑Skills und deren Metadaten. Hier werden auch Freischaltungen je Agent/Workspace verwaltet.
6. **Secrets‑Broker:** Speichert langfristige Geheimnisse (OAuth‑Refresh‑Tokens, API‑Schlüssel). Gibt pro Aufruf nur kurzlebige, parametergebundene Handles an Runner aus.
7. **Scheduler:** Führt wiederverwendbare Verträge zeitgesteuert oder ereignisgesteuert unter strenger Policy aus.
8. **Audit‑Log:** Unveränderliche Protokolle aller Aktivitäten, Entscheidungsvorgänge, Verträge, Genehmigungen und Artifact‑Erstellungen.

![High‑Level‑Architekturdiagramm](./assets/architecture_diagram.png)

Abbildung 1: High‑Level‑Architekturdiagramm.


## 6 Verträge: einheitliche Autorisierungsobjekte

### 6.1 Vertragsarten

- **Einmaliger Vertrag (One‑Shot):** Gilt für eine einzelne Aktion. Parameter müssen exakt mit dem bei der Genehmigung gespeicherten Hash übereinstimmen. Beispiel: „Sende diese E‑Mail jetzt“.
- **Wiederverwendbarer Vertrag:** Für geplante oder wiederkehrende Aktionen wie Cron‑Jobs. Er definiert Constraints (z. B. erlaubte Suchanfragen, erlaubte Empfänger), Budgets und zeitliche Nutzungslimits. Er ist an Policy‑ und Skill‑Versionen gebunden; bei Änderungen pausiert der Job und erfordert erneute Genehmigung.

### 6.2 Bindungsmodi

- **Exakt:** Der Parameter‑Hash muss mit dem genehmigten Wert übereinstimmen. Erhöht Sicherheit, verringert aber Flexibilität.
- **Begrenzt:** Parameter müssen in einer erlaubten Menge liegen (z. B. Abfrage‑Allowlist, Maximalanzahl von Ergebnissen). Ideal für wiederkehrende Jobs, die variable Eingaben benötigen.

### 6.3 Genehmigungs‑UX

Verträge werden dem Nutzer in der Control UI als „Permissionskarte“ mit folgenden Elementen präsentiert:

- Art des Vertrags (einmalig / wiederverwendbar) und Zweck.
- Werkzeuge, Parametergrenzen, Ziel‑Allowlisten und Budgets.  
- Datenhandhabungsregeln: keine Anhänge, redaktion von Secrets, Höchstgröße.  
- Pins auf Policy‑ und Skill‑Versionen mit Rollback‑Schutz (Downgrades erfordern explizite Neu‑Genehmigung).  
- Optionale Testausführung („Dry Run“).

Der Nutzer kann den Vertrag genehmigen, anpassen oder ablehnen. Bei Änderungen (z. B. durch Plugin‑Updates) wird ein Diff angezeigt und der Nutzer muss erneut zustimmen.


## 7 Policy‑Engine: Capability Model, Budgets und Data Guards

Die Policy‑Engine ist der zentrale „Wächter“ zwischen Engine und Runner:

- **Capabilities** definieren atomare Zugriffsrechte, z. B. `cap.email.read` mit Query‑Allowlist und max. Ergebnissen oder `cap.fs.write` mit einem erlaubten Pfad.  
- **Modi:** Interaktive Sitzungen vs. geplante Jobs. Geplante Jobs haben strengere Limits (z. B. Verbot von High‑Risk‑Tools).  
- **Budgets:** Limiten für Tool‑Aufrufe, Laufzeit, Nachrichten, Bytes, Token und Kosten.  
- **Data Guards:** Prüfen ein‑ und ausgehende Inhalte (Prompt‑Injection, PII, Geheimnisse). Sie können Nachrichten kürzen oder blockieren, wenn sensible Daten gefunden werden.  

Data Guards arbeiten **deny‑by‑default beim Egress**: Ausgehende Inhalte müssen in erlaubte, typisierte Felder passen (keine rohen Blobs) und werden sowohl im Rohformat als auch nach Dekodierung geprüft (z. B. base64/hex/url/gzip). Eingaben und Tool‑Outputs werden **taint‑gelabelt**; tainted Daten dürfen das System nur verlassen, wenn der Vertrag diese Quelle explizit erlaubt oder der Nutzer die konkrete Ausgabe genehmigt. Artifacts werden per Hash referenziert; Inhalte dürfen ohne explizite Genehmigung nicht exfiltriert werden.

Die Policy‑Engine speichert jede Entscheidung im Audit‑Log. Bei einem Tool‑Aufruf werden folgende Schritte ausgeführt:

1. Vertrag laden und prüfen: Ist er gültig, nicht abgelaufen und genehmigt?  
2. Principal‑Abgleich: Stimmt der Principal (Session / Job) mit dem im Vertrag überein?  
3. Parametervalidierung: Entspricht der Aufruf dem Binde‑Modus und den Constraints?  
4. Budgetprüfung: Sind Limits für diesen Lauf noch nicht überschritten?  
5. Risikoklasse: High‑Risk‑Tools erfordern interaktive Genehmigung.  
6. Ergebnis protokollieren und Entscheidung zurückgeben (Allow / Deny / Approval).  

Bevor die Policy‑Prüfung startet, validiert die Engine alle Tool‑Vorschläge und Entscheidungsobjekte gegen das Schema. Nur schema‑konforme Outputs gelangen in die Evaluation; fehlerhafte Antworten werden verworfen oder erneut angefordert.
Um Serialisierungsdrift zu verhindern, werden Tool‑Calls **kanonisiert** (deterministische Kodierung und Schlüsselreihenfolge) und gehasht. Die Policy‑Entscheidung ist an diesen kanonischen Hash gebunden, und der Runner berechnet und prüft ihn vor der Ausführung; Abweichungen werden abgelehnt.

### 7.1 Structured Outputs (Schema‑First LLM I/O)

Die Engine ruft das LLM ausschließlich mit **strukturierten Ausgabeschemata** auf. Tool‑Vorschläge, Vertragsentwürfe, Risiko‑Einschätzungen und Artifact‑Metadaten müssen ein validierbares Objekt liefern (z. B. JSON‑Schema oder Pydantic‑Modelle). Erst **nach erfolgreicher Validierung** wird die Policy‑Prüfung ausgeführt; fehlerhafte Antworten werden verworfen und mit einem engeren Schema erneut angefordert. Dadurch sinken Parsing‑Fehler, Halluzinations‑Syntax und inkonsistente Parameter.

Structured Outputs unterstützen zudem reproduzierbare Audits: Jede Entscheidung basiert auf einem bekannten Datentyp, der in Logs und Artifacts konsistent erfasst wird. In der Praxis lassen sich Schema‑Constraints (Enums, Pattern, Range‑Checks) direkt an Verträge koppeln und vor der Policy validieren.

**LLM‑Unterstützung (Beispiele):** OpenAI Structured Outputs, Gemini Structured Output und Mistral Structured Outputs unterstützen schema‑gebundene Antworten. Siehe: [OpenAI Structured Outputs](https://openai.com/index/introducing-structured-outputs-in-the-api/), [Gemini Structured Output](https://ai.google.dev/gemini-api/docs/structured-output), [Mistral Structured Outputs](https://docs.mistral.ai/capabilities/structured-output/structured_output_overview/).

## 8 Vermittelte Geheimnisse: Zero‑Token‑Exposure

Das Framework implementiert einen **Secrets‑Broker**, der langfristige Schlüssel verwaltet und nur kurzlebige Handles ausgibt. Dies verhindert, dass Tokens versehentlich in Prompt‑Kontexte gelangen oder über das Netzwerk abfließen. Der Ablauf sieht so aus:

1. **Policy erteilt Erlaubnis:** Bei erfolgreicher Prüfung generiert die Policy einen internen Entscheidungseintrag.  
2. **Runner fordert Handle an:** Er ruft `AcquireHandle(decision_id, tool_call_id)` beim Broker auf.  
3. **Broker prüft:** Ist die Entscheidung gültig? Stimmt der Runner‑Identität? Sind die Parameter gebunden?  
4. **Broker gibt Handle zurück:** Der Handle ist nur für diesen einen Aufruf, das spezifische Werkzeug, den Parameter‑Hash (aus dem kanonisierten Tool‑Call abgeleitet) und eine kurze TTL gültig.  
5. **Runner führt Aktion aus:** Mit dem Handle ruft der Runner intern die API auf.  
6. **Handle verliert seine Gültigkeit:** Er kann nicht wiederverwendet oder außerhalb des Runners exfiltriert werden.

Das LLM erhält lediglich die `decision_id` und Metadaten, aber niemals den Handle selbst. Der Broker fungiert als **Token‑Delegationsschicht**: pro Tool‑Call wird ein einmaliger, eng gebundener Delegations‑Handle ausgestellt, der ausschließlich im Runner verwendbar ist.

### 8.1 Secure Secret Provisioning (Control UI Flow)

Wenn ein Nutzer einen Skill aktiviert, der API‑Keys oder Tokens benötigt, nutzt das System einen **dedizierten Control UI‑Flow** zur Secret‑Erfassung. Das Eingabeformular wird vom Gateway bereitgestellt und über den gepaarten, vertrauenswürdigen Kanal ausgeliefert. Secrets werden direkt an den **Secrets‑Broker** über mTLS mit Origin/CSRF‑Binding übertragen, verschlüsselt gespeichert und gelangen **nie** in den LLM‑Kontext. Die Engine erhält lediglich einen Verweis (z. B. `secret_id`) und kann pro Tool‑Call kurzlebige Handles anfordern.

Damit gilt:

- Secrets werden niemals per Chat übertragen.
- Das LLM sieht keine Tokens oder API‑Keys.
- Der Broker kann Scopes, Rotation und Revocation erzwingen, ohne Prompts anzupassen.

Im Gegensatz zu Token‑Weitergabe (wie bei OpenClaw) wird so sichergestellt, dass Angreifer selbst beim Abfangen des Handles nichts anfangen können; sie bräuchten zusätzlich die Identität des Runners, den Entscheidungseintrag und den Parameter‑Hash.


## 9 Runner: Ausführungsbereiche, Egress‑Kontrolle und Output‑Sanitizer

Runner sind die „Werkbank“ des Frameworks. Für jede Werkzeugklasse existiert ein spezieller Runner (z. B. E‑Mail‑Runner, Filesystem‑Runner, Slack‑Runner). Der Runner führt ein Werkzeug in einer isolierten Umgebung aus und hat folgende Pflichten:

- **Sandboxing:** Standardmäßig wird ein **WASM‑Runtime** genutzt. Der Runner selbst läuft in einem separaten Container mit minimalen Rechten.  
- **Runner‑Hardening‑Baseline:** `no-new-privileges`, alle Linux‑Capabilities droppen, strikte `seccomp`‑Allowlist, rootless Ausführung, read‑only Root‑Filesystem mit expliziten Schreib‑Mounts sowie keine Host‑Sockets.  
- **Egress‑Filter:** Der Runner darf nur zu in der Policy erlaubten Hosts/Ports verbinden. Alle anderen Netzverbindungen sind verboten.  
- **Ressourcenlimits:** CPU‑Zeit, Speicher und Dateigrößen sind begrenzt.  
- **Filesystem‑Mounts:** Schreibzugriff nur auf definierte Pfade; Leserechte können per Pattern eingeschränkt werden.  
- **Output‑Sanitizer:** Vor der Rückgabe an die Engine werden Tokens, Auth‑Header, API‑Schlüssel, PII und andere definierte Patterns entfernt oder maskiert. Große Ausgaben werden als Artifacts abgelegt.  

Netzwerk ist **standardmäßig aus**; Egress erfordert explizite Policy‑Allowlists. Jeder Runner protokolliert den Hardening‑Profil‑Hash/die Version im Audit‑Log und schlägt fehl, wenn erforderliche Controls fehlen.


## 10 Skills und Plugin‑Modell

### 10.1 WASM‑Skills

Jedes Skill besteht aus einer signierten **WASM‑Modul**‐Datei und einem **Manifest**. Das Manifest definiert:

- `skill_id`, Version, Herausgeber (Publisher‑ID) und Signatur.  
- Eine Liste der Werkzeuge (`tools`), ihre Namen, Eingabe‑ und Ausgabeschemata und eine Risikoklasse.  
- Erforderliche Capabilities (`required_capabilities`) und erlaubte Egress‑Ziele (`egress_requirements`).  

Die Skill‑Registry verifiziert beim Import die Signatur **und die Publisher‑Trust‑Chain** und prüft die Eintragung im Transparenz‑Log (lokal/privat standardmäßig). Wird ein Skill installiert, muss der Nutzer ihn in der Control UI pro Agent / Workspace aktivieren. Werkzeuge dürfen nur die im Manifest deklarierten Capabilities nutzen; andere Aufrufe werden von der Policy verweigert.

Benötigt ein Skill API‑Keys oder Tokens, werden Secrets über den in **Abschnitt 8.1** beschriebenen Control UI‑Flow bereitgestellt und gelangen niemals in den LLM‑Kontext.

### 10.2 Native Companion Services

Braucht ein Skill nativen Zugriff (z. B. Hardware, Browser‑Automation), so muss der Entwickler eine **zweiteilige** Lösung bereitstellen:

- **WASM‑Teil:** Enthält das Orchestrations‑ und Logik‑Layer. Dieser Teil definiert das Werkzeug und ruft nur host‑Funktionen an.  
- **Native Companion Service:** Läuft als separater Prozess oder Container, besitzt begrenzte Rechte und exponiert nur eine minimale API. Dieser Service ist per mTLS authentifiziert; jede Anfrage muss einen gültigen Entscheidungseintrag vorlegen. Der Service prüft Parametergrenzen, Egress‑Filter und ruft die benötigten nativen APIs auf.

Durch diese Trennung kann native Code sicher verwaltet werden, ohne dass das WASM‑Plugin unkontrollierten Zugang zum Host erhält.

### 10.3 MCP‑Server als Skills (optional)

Statt eines eigenen Plugin‑Ökosystems können **MCP‑Server** als Skills modelliert werden. Jeder MCP‑Server wird wie ein Skill registriert und erhält ein Manifest mit Tool‑Schemas, Auth‑Methoden und Capability‑Mapping. Die Policy‑Engine prüft **jeden** MCP‑Tool‑Call; der Runner fungiert als Proxy und erzwingt Parametergrenzen, Budgets und Egress‑Allowlists.

Es gibt zwei Betriebsarten:

- **Lokale MCP‑Server:** laufen in einer Sandbox oder als Companion‑Service mit minimalen Rechten. Der Zugriff erfolgt über mTLS oder lokale Socket‑Policy.
- **Remote MCP‑Server:** werden nur über Allowlists angesprochen, benötigen starke Authentifizierung (mTLS/OAuth) und erhalten pro Aufruf einen delegierten Handle vom Secrets‑Broker. Tokens bleiben beim Broker; der LLM sieht keine Credentials.

So lässt sich die Flexibilität von MCP nutzen, ohne die Sicherheitsgarantien der Vertragsarchitektur aufzugeben.


## 11 Zeitgesteuerte und ereignisgesteuerte Automatisierung

Das Framework unterstützt Cron‑Jobs, Event‑Trigger (Webhook, Datenbank‑Änderungen etc.), **konditionale Regeln** und One‑Shot‑Timer. Kernelemente:

- **Job‑Principals:** Jede geplante Aufgabe läuft als eigener Principal (`job:<id>`). Ein Job hat ein zugehöriges wiederverwendbares Vertragsobjekt, das Tools, Parameter‑Allowlisten, Budgets und Datenrichtlinien definiert.
- **Misfire‑Strategien und Zeitverwaltung:** Zeitpläne werden in UTC gespeichert, aber in der lokalen Zeitzone interpretiert. Job‑Verpasste Ausführungen können übersprungen oder nachgeholt werden, je nach Konfiguration.
- **Strikt limitierte Budgets:** Cron‑Jobs haben kleinere Budgets als interaktive Sitzungen. Keine Shell‑Ausführung und keine neuen Capabilities ohne Genehmigung.
- **Idempotenz und Outbox:** Jede Side‑Effect‑Aktion hat einen Idempotenz‑Key (`job_run_id + action_hash`). Retries prüfen eine Outbox, bevor gesendet, gepostet oder mutiert wird.  

**Hintergrund‑Workflow (Scheduled Job, Beispiel):**

1. **Scheduler startet Job:** Principal `job:<id>` wird aktiviert und Budgets werden gesetzt.  
2. **Tool‑Call 1:** z. B. `gmail.search` → Policy prüft Vertrag, Parametergrenzen, Budget.  
3. **Runner führt aus:** Handle vom Secrets‑Broker, Output‑Sanitizer aktiv.  
4. **LLM analysiert Ergebnis:** erstellt Zusammenfassung oder plant nächste Aktion.  
5. **Tool‑Call 2:** z. B. `gmail.getMessage` → Policy prüft erneut.  
6. **Tool‑Call 3:** z. B. `slack.post` → nur erlaubt, wenn der Vertrag Kanal und Umfang begrenzt.  
7. **Audit‑Log:** jeder Schritt wird protokolliert; Artifacts werden referenziert.  
8. **Abweichung:** verletzt ein Call die Regeln, pausiert der Job und verlangt Re‑Approval.

Bei Änderungen an Tools, Policies, Skill‑Versionen oder Parametern pausiert der Scheduler den Job und zeigt dem Nutzer einen Änderungs‑Diff zur erneuten Freigabe.


## 12 Multi‑Agent‑Unterstützung und Orchestrierung

Das Identitätsmodell unterscheidet **Benutzer**, **Agenten** und **Principals** (Sitzung/Job). Jeder Tool‑Call ist an einen Principal gebunden, wodurch Rechte und Budgets präzise getrennt werden können.

### 12.1 Agentenprofile

Jeder Agent ist ein konfigurierbares „Profil“:

- **Persona:** Einstellung für Ton, Style und Ziele.  
- **Freigeschaltete Skills:** Liste der aktivierten WASM‑Skills.  
- **Policy‑Profil:** Festlegung der Budgets und High‑Risk‑Regeln.  
- **Memory‑Scope:** Definiert, welche Speicherbereiche (Sitzung, Agent, Workspace, Benutzer) gelesen oder beschrieben werden dürfen.  
- **Zulässige Kanäle:** Welche Messenger oder Kommunikationswege der Agent nutzen darf.  

Die Engine kann mehrere Agenten parallel verwalten. Nachrichten werden je nach Workspace/Channel an den entsprechenden Agenten geleitet.

### 12.2 Orchestrierungsmuster

- **Einzel‑Engine, mehrere Agenten:** Ein Engine‑Prozess hostet mehrere Agenten. Die Policy trennt Capabilities und Speicherzugriffe pro Agent.  
- **Supervisor/Worker:** Ein Supervisor‑Agent mit minimalen Rechten plant Aufgaben und delegiert sie an spezialisierte Worker (z. B. Code‑Generator, Prüfer, Tester). So lassen sich komplexe Aufgaben sicher in separate Schritte aufteilen, wobei jeder Worker nur die minimal nötigen Berechtigungen besitzt.

### 12.3 Cross‑Agent‑Kommunikation

Agenten können strukturiert miteinander kommunizieren (Artifacts, strukturierte Ergebnisse), jedoch werden interne Chat‑Nachrichten als untrusted Input behandelt. Datenübergaben erfolgen über Artifact‑basierte Schnittstellen; Genehmigungen bleiben agentenspezifisch.


## 13 Artifact‑basierte Ausgaben

Anstatt große Datenmengen direkt im Chat zu senden, legt das Framework **Artifacts** an. Ein Artifact ist ein strukturierter Datensatz mit Metadaten (Typ, Größe, Hash, Speicherort, Zugriffsrichtlinie). Artifacts sind **standardmäßig untrusted**: sie tragen Provenienz, werden per Hash gespeichert, beim Schreiben und Lesen gescannt und dürfen nur mit expliziter Allowlist oder Genehmigung erneut in den Modell‑Kontext oder nach außen eingespeist werden.  

Beispiele für Artifact‑Typen:

- **Patch:** Code‑Diff (z. B. im Unified‑Diff‑Format).  
- **Report:** Markup‑Datei (z. B. Markdown oder PDF) mit detaillierten Inhalten.  
- **Dataset:** JSON‑ oder CSV‑Datei.  
- **LogBundle:** Sammlung von Log‑Dateien oder Testergebnissen.  
- **DraftMessage:** Entwurf für eine Nachricht, die vom Nutzer überprüft wird.  

Der Vertrag definiert maximale Größen, erlaubte Dateitypen und Aufbewahrungsdauer. Die Engine sendet nur eine kurze Zusammenfassung und, falls gewünscht, eine Vorschau (z. B. die ersten Zeilen eines Patches) sowie einen Link, um das Artifact in der UI zu öffnen. Dadurch werden Chat‑Kontexte geschont und sensible Daten vor dem LLM verborgen.


## 14 Speicherbereiche und Promotion

Das Framework unterscheidet verschiedene Speicherbereiche:

- **Sitzungsspeicher:** Flüchtige Notizen für eine laufende Konversation. Automatisch gelöscht nach Beendigung der Sitzung.
- **Agentenspeicher:** Langfristige Präferenzen und Fakten, die der jeweilige Agent nutzen darf.  
- **Workspace‑Speicher:** Geteiltes Wissen in einer Organisation.  
- **Benutzerspeicher:** Personalisierte Informationen, nur auf ausdrücklichen Wunsch des Nutzers gespeichert.

Speicherpromotion erfordert explizite Bestätigung des Nutzers; das LLM kann nicht selbstständig neue Fakten dauerhaft speichern. Darüber hinaus wird jeder Speicherinhalt als untrusted betrachtet. Beim Abruf werden Herkunft und Integrität geprüft; verdächtige oder bösartige Einträge können vom Nutzer zurückgezogen werden.


## 15 Audit, Observability und Forensics

Jede Interaktion erzeugt einen Audit‑Eintrag. Einträge umfassen:  

- Vertragsvorschläge, Änderungen und Genehmigungen.  
- Policy‑Entscheidungen (Allow/Deny/Approval).  
- Tool‑Aufrufe (ID, Parameter‑Hash, Ergebnis‑Hash).  
- Artifact‑Erzeugung und Zugriffe.  
- Job‑Läufe und Scheduler‑Ereignisse.  
- Ausgehende Nachrichten (Ziel, Inhaltshash).  

Die Audit‑Log ist schreibgeschützt; nur Append‑Operationen sind zulässig. Observability wird durch strukturierte Logs, Metriken (z. B. Laufzeit, Anzahl Denials, Kosten) und verteilte Traces erreicht. Forensics‑Tools können anhand der Audit‑Log nachvollziehen, wer wann welche Aktion genehmigt hat und welche Daten das System verlassen haben.


## 16 Referenz‑Workflows

Um die Architektur greifbar zu machen, werden im Folgenden zwei typische Workflows mit Verträgen dargestellt.

### 16.1 Nachtlicher Ops‑Digest (wiederverwendbarer Vertrag)

**Beschreibung:** Jeden Abend um 02:00 Uhr soll der Agent alle E‑Mails vom Absender `alerts@corp.com` der letzten 24 Stunden durchsuchen, max. 50 Nachrichten abrufen, eine Zusammenfassung erstellen und diese als Slack‑Nachricht in den Kanal `#ops-alerts` posten.  

**Vertrag:**

- **Tools:** `gmail.search` (bounded – Query‑Allowlist `from:alerts@corp.com newer_than:1d label:ops`, max 50 Ergebnisse), `gmail.getMessage` (bounded – nur Felder `subject`, `from`, `date`, `snippet`, max 10 Nachrichten), `slack.post` (bounded – nur Channel `#ops-alerts`, max 4000 Zeichen).  
- **Budgets:** max 20 Tool‑Aufrufe, max 60 Sekunden Laufzeit, max 1 ausgehende Nachricht.  
- **Datenbehandlung:** Keine Anhänge, keine vollständigen E‑Mail‑Bodies, Reduktion sensibler Daten.  
- **Pins:** Policy‑Hash, Tool‑Catalog‑Hash und Skill‑Set‑Hash. Bei Änderungen pausiert der Job.  
- **Genehmigung:** Einmal über die Control UI durch den Nutzer; anschließend läuft der Job unsupervised, solange er die Grenzen nicht verletzt.  

**Sicherheit:** Selbst wenn E‑Mails bösartige Anweisungen enthalten, kann der Job nur vordefinierte Daten abrufen und eine Nachricht in einen einzigen Slack‑Kanal mit begrenztem Umfang posten. Bei jeder Abweichung (z. B. neue Query, größeres Ergebnis, Änderung des Channels) wird der Job pausiert und eine erneute Genehmigung erforderlich. 

### 16.2 Coding‑Aufgabe mit unvorhersehbarer Ausgabe (Artifact‑basiert)

**Beschreibung:** Der Nutzer bittet den Agenten, eine neue Funktion zu implementieren. Diese Aufgabe kann große Code‑Patches generieren und erfordert Tests und Reviews.  

**Empfohlener Workflow:**

1. **Planung:** Das LLM erstellt eine Liste der zu bearbeitenden Dateien, eine kurze Beschreibung der Änderungen und die Teststrategie.  
2. **Patch‑Erzeugung:** Das Tool `codegen.patch` generiert einen Diff basierend auf den Plänen. Der Diff wird als Artifact gespeichert. Parameterbeschränkungen (Max Dateianzahl, Max Diff‑Größe, keine Änderungen an `.env` oder Schlüsseldateien) sind Teil des Vertrags.  
3. **Validierung:** Ein Runner führt Tests (`pnpm test`, `pnpm lint`) in einer isolierten Umgebung aus (kein Netzwerk). Testprotokolle werden als Artifact abgelegt.  
4. **Review:** Optional wird ein zweiter Agent (Reviewer) mit Lesezugriff auf den Patch‑Artifact beauftragt, um Feedback zu geben.  
5. **Anwendung:** Ein dritter Agent (Applier) darf den Patch nur anwenden (z. B. via `git apply`), wenn der Nutzer über die UI einen One‑Shot‑Vertrag genehmigt.  
6. **Zusammenfassung:** Das LLM erstellt eine Kurzbeschreibung der Änderungen, die geänderten Dateien und Hinweise zum Testen.  

**Sicherheit:** Die Generierung, Tests und Review laufen ohne Schreibzugriff auf das Repository. Nur der Applier hat begrenzte Schreibrechte, und seine Aktion erfordert eine separate Genehmigung. So reduziert sich das Risiko, dass ein Fehler oder eine Prompt‑Injektion unkontrolliert Code in die Produktionsumgebung einbringt.



## 17 Pseudocode‑Beispiele

Die folgenden Dateien enthalten technologie‑neutrale Abläufe und dienen als Implementierungsleitfaden:

- Interaktiver E‑Mail‑Flow (One‑Shot): [01_interactive_email_flow.md](../pseudo_code/01_interactive_email_flow.md)
- Geplanter Digest‑Job (Reusable): [02_scheduled_digest_job.md](../pseudo_code/02_scheduled_digest_job.md)
- Policy/Runner‑Pipeline: [03_policy_toolcall_pipeline.md](../pseudo_code/03_policy_toolcall_pipeline.md)

## 18 Deployment und Monorepo‑Struktur

Siehe auch die Compose‑Deployment‑Notiz: [deployment_docker_compose.md](./deployment_docker_compose.md).

Für die Zusammenarbeit im GitHub‑Repository wird eine klare Struktur empfohlen:

```
repo/
  docs/whitepaper_de.md              # Whitepaper (Deutsch)
  docs/whitepaper_en.md              # Whitepaper (English)
  docs/assets/architecture_diagram.png
  apps/
    gateway/                         # Channels, UI, Pairing
    control-ui/                      # Web-UI für Genehmigungen, Jobs, Audit
    engine/                          # Agenten-Loop
    policy/                          # Policy-Engine
    runner/                          # Tool-Ausführung (Runner-Pool)
    worker/                          # Hintergrund-Worker für Jobs/Queues
    broker/                          # Secrets-Broker
    scheduler/                       # Cron/Event Scheduler
  packages/
    core/                            # Gemeinsame Typen und Schemas
    agent-runtime/                   # Agent-Laufzeit, Zustände, Session-Handling
    contracts/                       # Hashing, Diff, Validierung
    policy/                          # DSL und Evaluator
    scheduler-lib/                   # Scheduling-Utilities, Kalenderlogik
    queue/                           # Job- und Tool-Dispatch
    wasm-runtime/                    # WASM-Ausführungsumgebung
    tools-sdk/                       # SDK für Tool-Adapter und MCP-Bridges
    skill-sdk/                       # Manifest- und Tool-Schema-Hilfen
    artifacts/                       # Artifact storage und Scanner
    audit/                           # Audit-Log-Implementierung
    memory/                          # Speicherverwaltung
    testing/                         # Test-Harnesses und Sicherheits-Suites
  skills/
    example-wasm-skill/
  companions/
    example-native-companion/
  examples/
    nightly-ops-digest/
    codegen-patch-workflow/
```

Diese Struktur erleichtert die Trennung von Komponenten, ermöglicht CI‑Tests für jede Schicht und schafft einen klaren Einstiegspunkt für Beiträge.

**Test‑Strategien:** Wir empfehlen Policy‑Regressionstests (Allow/Deny‑Matrix), Vertrag‑Diff‑Tests, einen Prompt‑Injection‑Korpus, Sandbox‑Escape‑Tests, sowie End‑to‑End‑Workflows mit Artifacts und MCP/WASM‑Skills. Sicherheitsrelevante Änderungen müssen alle Tests bestehen, bevor neue Skills oder Policies freigegeben werden.



## 19 Glossar

- **Agent:** Konfigurierter Assistent mit Persona, Skills und Policy‑Profil.
- **Principal:** Sicherheitsidentität für Sitzung oder Job, an die Tool‑Aufrufe gebunden sind.
- **Vertrag (Contract):** Autorisierungsobjekt mit Tools, Parametern, Budgets und Datenregeln.
- **Capability:** Feingranularer Zugriff auf eine Tool‑Klasse mit Parametergrenzen.
- **Policy‑Engine:** Bewertet Tool‑Aufrufe gegen Verträge, Budgets und Risikoklassen.
- **Runner:** Isolierte Ausführungsumgebung für Tools (WASM/Container).
- **Runner‑Hardening‑Baseline:** Verbindliches Sicherheitsprofil für Runner (seccomp‑Allowlist, no‑new‑privileges, read‑only FS, rootless, Netzwerk standardmäßig aus).
- **Secrets‑Broker:** Verwaltet langfristige Geheimnisse und gibt kurzlebige Handles aus.
- **Skill:** Signiertes Tool‑Paket (WASM oder MCP‑Server) mit Manifest.
- **Artifact:** Externer Datensatz für große Ausgaben (Patch, Report, LogBundle).
- **Untrusted Artefact:** Artifact, das standardmäßig als untrusted gilt; per Hash mit Provenienz gespeichert, beim Schreiben/Lesen gescannt und nur mit expliziter Allowlist oder Genehmigung erneut ingestiert.
- **Job‑Principal:** Principal eines geplanten Jobs mit restriktiven Rechten.
- **Control UI:** Vertrauenswürdige Oberfläche für Genehmigungen und Pairing.
- **Publisher‑Trust‑Chain:** Verifizierte Herkunft der Publisher‑Keys (Root in Allowlist oder auditierter Root) plus Transparenz‑Log‑Inklusion und Revocation‑Prüfungen.
- **Pairing‑Token:** Kurzlebiger, einmaliger Code zur Bindung eines Geräts an das Gateway.
- **Gerätegebundenes Pairing:** Pairing‑Flow mit Besitznachweis des Geräteschlüssels sowie strikten Origin/CSRF‑Checks.
- **Data Guards:** Filter für Prompt‑Injection, PII und Secrets auf Ein‑/Ausgaben.
- **Structured Output:** Schema‑gebundene LLM‑Antworten für Tool‑Aufrufe und Entscheidungen.
- **Kanonischer Tool‑Call‑Hash:** Deterministischer Hash des kanonisierten Tool‑Calls zur Bindung von Policy‑Entscheidung und Runner‑Ausführung.
- **Taint‑Label:** Herkunftsmarker für Daten aus Tools, Dateien oder externen Quellen, die strengere Egress‑Kontrollen erfordern.
- **Egress‑Schema:** Allowlist‑basiertes, typisiertes Ausgabeschema, das vor dem Verlassen des Systems erzwungen wird.
- **Rollback‑Protection Pinning:** Policy/Skill‑Pinning mit **Version‑Floor** und **signierter Release‑Sequenz**, das Downgrades hart blockiert und eine explizite Neu‑Genehmigung samt Diff erfordert; Rollback‑Versuche werden protokolliert und können Alarme auslösen.

## 20 Ausblick und Roadmap

Die vorgestellte Architektur bildet die Grundlage für ein sicheres Agentenframework. In zukünftigen Versionen sollen folgende Themen vertieft werden:

- **DSL für Richtlinien (v0.4):** Eine menschenlesbare Sprache (z. B. YAML), die in Policy‑Regeln übersetzt wird.  
- **Protokoll für Native Companions (v0.4):** Definition der mTLS‑Handshake‑ und Authentifizierungsmechanismen sowie des Anfragemodells.  
- **Vertrag‑Diff‑Algorithmen (v0.4):** Um Änderungen zwischen Verträgen zuverlässig darzustellen.  
- **Transparenz‑Log für Skills (v0.5):** Öffentliche Protokolle der Skill‑Signaturen und ihrer Historie.  
- **Anomalie‑Erkennung (v0.5):** Automatische Pausierung von Jobs bei ungewöhnlichem Verhalten.  
- **Multi‑Tenant‑Hardening (v0.5):** Richtlinien für Mandantentrennung und verschlüsselte Artifact‑Speicher.  


## 21 Schlussbemerkung

Die wachsende Verbreitung autonomer Agenten erfordert einen Paradigmenwechsel: Weg vom „Assistenten mit allen Rechten“ hin zu **vertraglichen Agenten**, die nur das tun dürfen, was explizit genehmigt wurde. Durch Verträge, klare Capabilities, einen vermittelnden Secrets‑Broker, isolierte Runner, signierte WASM‑Skills und strenge Audit‑Logs reduziert das vorgeschlagene Framework die Angriffsfläche drastisch. Gleichzeitig bleibt die Benutzererfahrung vertraut: ein lokaler Gateway‑Chat mit Control UI, Pairing und Skills – nur eben mit dem Sicherheitsniveau, das moderne Anwendungen verlangen.

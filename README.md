# CDS.Security

## 1.2 Implementation

### Authentication method

Vi har valgt at bruge cookie baseret autentificering (ASP.NET core) med en rollebaseret autorisation.
Dette virker på den måde at brugeren udfylder login formularen i React som sender brugernavn og adgangskode til Post, Dette gør at API’en finder brugeren i databasen og verificerer adgangskoden, hvis det går igennem opretter den en Claims Principal med 3 claims, bruger id, brugernavn og rolle, derefter udsteder Sign In Async en krypteret cookie, denne cookie er HttpOnly så Javascript kan ikke læse den, det hjælper imode XSS tyveri som normalt bruger Javascript til at gå efter cookies.
Klienten kalder fetch med credentials: “include”, dette betyder at browseren automatisk sender cookien med ved hvert kald, hvis man genindlæser siden kalder klienten en Get som autentificerer at det er den rigtige person og ved log out kalder den POST som sletter cookien.

### Password handling and storage

Adgangskoderne er håndteret med BCrypt som gør at de aldrig bliver gemt som klartekst, men de bliver gemt som tilfældigt genereret salt og en work factor som gør hashing langsomt så det er dyrt at tvinge igennem.

Adgangskoderne bliver lagret med kun Password Hash som gemmes i SQLite Tabellen Users, dette betyder at adgangskoden ikke findes op Account User eller Account Response, så hverken adgangskoden eller hash bliver sendt tilbage.

Der er et krav til adgangskoder og det er at de skal være 12 tegn lange.

### Screenshots demonstrating key functionality
Loginskærm:

![img.png](images/img.png)

Forkert password:

![img_1.png](images/img_1.png)

Successfuldt login:

![img_2.png](images/img_2.png)

Efter oprettelse af ny bruger:

![img_3.png](images/img_3.png)

---

# CDS.Infrastructure

## 2.1 The Company's network

I dette afsnit beskriver vi netværksdesignet til Kvist & Bjælke ApS, med fokus på IP-adressering og subnetting. Målet er at lave en struktureret og sikker netværksløsning, hvor virksomhedens enheder er delt op i passende netværk, og hvor der er plads til at vokse.

### 2.1.1 VLAN plan
`I denne del står der vi skulle lave en IP-adresseringsplan, men efter snak med Henrik, så blev der ment VLAN-plan.`

Vi har lavet en VLAN-plan til Kvist & Bjælke ApS. Planen viser, hvordan enhederne er delt op i logiske netværk, og hvordan IP-adresser, gateways og DHCP er fordelt. Vi har valgt at holde alle netværk inden for det private adresseområde 10.5.0.0/16, så planen er overskuelig og nem at udvide.

| VLAN-ID | Navn | CIDR | Subnetmaske | Gateway | IP-tildeling | Enheder |
|---|---|---|---|---|---|---|
| 570 | Clients | 10.5.70.0/24 | 255.255.255.0 | 10.5.70.5 | DHCP | Stationære og bærbare computere |
| 571 | Servers | 10.5.71.0/24 | 255.255.255.0 | 10.5.71.5 | Statisk | Virksomhedens interne servere |
| 572 | Voice | 10.5.72.0/26 | 255.255.255.192 | 10.5.72.1 | DHCP/Reservation | IP-telefoner |
| 573 | Printers | 10.5.73.0/29 | 255.255.255.248 | 10.5.73.1 | Statisk/Reservation | Netværksprintere |
| 574 | CCTV | 10.5.74.0/28 | 255.255.255.240 | 10.5.74.1 | Statisk/Reservation | Overvågningskameraer |
| 575 | Guests | 10.5.75.0/24 | 255.255.255.0 | 10.5.75.1 | DHCP | Gæsters enheder |
| 576 | MGMT | 10.5.76.0/24 | 255.255.255.0 | 10.5.76.1 | Statisk/Reservation | Switches, APs og administration af netværksudstyr |
| 577 | DMZ | 10.5.77.0/24 | 255.255.255.0 | 10.5.77.1 | Statisk | Servere der er tilgængelige udefra |

**Klienter – VLAN 570**
Computere og laptops ligger i samme klientnetværk, da de har nogenlunde de samme behov og skal tilgå virksomhedens interne systemer. Vi bruger DHCP, fordi det gør det meget nemmere at administrere adresserne.

**Servere – VLAN 571**
Serverne ligger for sig selv, fordi de indeholder interne systemer og data. Vi bruger statiske IP-adresser, så klienter og andre systemer altid kan finde serverne på de samme adresser.

**Telefoner og printere – VLAN 572 og 573**
IP-telefoner og printere har andre behov end almindelige computere. Med separate VLANs kan vi begrænse adgangen til dem og administrere dem hver for sig.

**Overvågning – VLAN 574**
Kameraerne er adskilt fra medarbejdernes computere, fordi de er specialiserede enheder, som kun bør kommunikere med de nødvendige overvågnings- og administrationssystemer.

**Gæster – VLAN 575**
Gæster får deres eget netværk med DHCP og internetadgang. Firewall-regler skal sørge for, at de ikke kan komme ind på interne servere, printere og administrationsudstyr.

**Administration – VLAN 576**
Netværksudstyr bliver administreret i et separat netværk, så almindelige brugere ikke bare kan tilgå switches, access points og firewallens administrationsgrænseflade.

**DMZ – VLAN 577**
Servere, der skal kunne nås udefra, placeres i en DMZ, så de er adskilt fra de interne servere. Hvis en DMZ-server bliver kompromitteret, kan angriberen ikke direkte nå det interne servernetværk.

### 2.1.2 Subnetting

Antallet af anvendelige hosts i et subnet beregnes som 2^(32 − præfiks) − 2, fordi netværksadressen og broadcast-adressen ikke kan tildeles til enheder.


**VLAN 575 (gæster):** Her har vi valgt et /24-netværk med 254 hostadresser, fordi antallet af gæster og deres enheder svinger meget fra dag til dag. Subnetmasken er 255.255.255.0, og netværksadressen er 10.5.75.0/24.

**VLAN 573 (printere):** Virksomheden har kun 3 printere, så her har vi valgt et lille /29-netværk med 6 hostadresser. Det er nok til de nuværende printere og giver plads til 3 ekstra. Subnetmasken er 255.255.255.248, og netværksadressen er 10.5.73.0/29.

**Plads til vækst:** Der er masser af ledig adresseplads i 10.5.0.0/16. Hvis virksomheden får flere printere, kan printernetværket udvides til fx et /28 med 14 hosts. Gæstenetværket er allerede stort nok til at klare mange besøgende på én gang.

---

## 2.2 Establishing a server on VLAN 571

Login-platformen er deployet på en virtuel maskine i Proxmox med følgende opsætning:

|  |  |
|---|---|
| Hypervisor | Proxmox VE 9.2 |
| Operativsystem | Ubuntu Server |
| Netværk | VLAN 571 (Servers) |
| IP-adresse | 10.5.71.95 |
| Hosting | Docker / Docker Compose |
| Valgt port | 8050 (webapplikation) og 8051 (backend/API) |

**Brugte porte:** Vi har valgt port 8050 til webapplikationen og 8051 til backend-API'et. Begge ligger i det tilladte interval 8000–8100, som firewallen tillader fra VLAN 570 til VLAN 571.

![img.png](images/SC3.png)

### Docker og deployment af login-platformen

Efter installationen af Ubuntu Server har vi installeret Docker og Docker Compose på serveren, så den er klar til at køre login-platformen.

Projektet ligger på serveren i mappen `/KBaps`. Applikationen startes med Docker Compose.

---

## 2.3 Establishing a client on VLAN 570

Vi har oprettet en  virtuel maskine (VM 120, `VLAN-570-client`) med Ubuntu Desktop, som er forbundet til VLAN 570. Med den kan vi teste, at vi kan nå login-platformen fra et andet netværk end det, serveren ligger på.



### Adgang til login-platformen

Klienten åbner platformen i Firefox på `http://10.5.71.95:8050`:

![img.png](images/SC1.png)

Efter login som `admin` vises brugeroversigten og formularen til at oprette konti. Det viser, at både frontend, backend og rollebaseret adgang virker fra klienten:

![img.png](images/SC2.png)

### Firewall og kommunikation mellem VLANs

**Hvorfor er VLAN 570 og 571 separate netværk?**
Klienter og servere har deres egne sikkerhedsbehov. Når de er adskilt i hver sit domæne, kan en klient som er komprimere ikke direkte se eller angribe serverne. Det giver også mindre trafik og gør netværket nemmere at administrere.

**Hvorfor kræver kommunikation mellem VLANs routing?**
Hvert VLAN er sit eget IP-subnet (I vores tilfælde fx. 10.5.70.0/24 og 10.5.71.0/24) og dermed sit eget domæne. Enheder i forskellige subnets kan ikke tale direkte sammen, så trafikken skal igennem en router (gateway), som sender requests videre mellem netværkene. Klienten sender derfor sine requests til sin gateway, som står for at route den videre til VLAN 571.

**Firewallens rolle:**
Firewallen styrer, hvilken trafik der må gå mellem netværkene. I vores opsætning er den allerede konfigureret til at tillade TCP 8000–8100 fra VLAN 570 til VLAN 571. Fx. i vores test kunne vi se, at vores `ping` ikke kom igennem.

**Hvorfor kun specifikke porte?**
Hvis man kun åbner de porte, der er nødvendige, mindsker man angrebsfladen. Klienterne kan kun nå den tjeneste, de har brug for. Vores test viser det tydeligt: `ping` fejler, mens `curl` og browser til port 8050 virker.

---

## 2.6 Testing and Documentation

### Server – VLAN 571

![img.png](images/SC3.png)

Ubuntu Server er installeret og i drift på serveren i VLAN 571. Serveren har den korrekte IP-konfiguration med adressen 10.5.71.95, som ligger i VLAN 571 (10.5.71.0/24). Docker er installeret og fungerer, hvilket ses ved, at `docker compose up -d` og `docker compose ps` kører uden fejl. Login-platformen kører inde i to Docker-containere, `kbaps-client` og `kbaps-backend`, som begge har status "Up". Platformen er tilgængelig på de valgte porte: `curl http://localhost:8050` returnerer webapplikationens HTML, og `curl http://localhost:8051` returnerer `"status":"ready"`.



### Client – VLAN 570


![img.png](images/SC1.png)

![img.png](images/SC2.png)

### Resultater af klientens tests:

| Test | Resultat |
|---|---|
| Klientens IP (VLAN 570) | 10.5.70.238  |
| Klientens gateway | 10.5.70.5 (ping: 0 % tab) |
| Serverens IP (VLAN 571) | 10.5.71.95 |
| Ping klient → server | 100 % tab (ICMP er blokeret) |
| `curl -v http://10.5.71.95:8050` | HTTP/1.1 200 OK, KBaps-siden returneres |
| Browsertest | Login-siden åbnede, og login virkede |

- **Korrekt IP-konfiguration:** Klienten har IP-adressen 10.5.70.238 og gatewayen 10.5.70.5 (ping: 0 % tab).
- **Adgang til login-platformen på VLAN 571:** Ja, `curl -v http://10.5.71.95:8050` giver HTTP/1.1 200 OK, og KBaps-siden returneres.
- **Platformens funktioner kan bruges fra klienten:** Ja, login-siden åbner i browseren, og login som `admin` lykkedes.
- **Test af forbindelse:** Forbindelsen blev testet ved at sende ping-anmodninger til serverne. Da vi testede forbindelsen fra klienten til serveren, mislykkedes ping-testen, fordi ICMP-trafik er blokeret i firewall'en. Det betyder, at ping-pakkerne bliver afvist, men ikke at forbindelsen mellem klient og server er usikker eller ikke fungerer. Blokeringen er en del af sikkerhedsopsætningen og forhindrer uautoriserede ICMP-anmodninger.




### Udfordringer og løsninger
Den basiske opsætning af Ubuntu/Proxmox tog lidt tid grundet overbelastning på Wi-Fi, som gjorde at vi konstant blev koblet af. Dette var der ikke nogen specifik løsning på andet end at prøve igen, eller vente til netværket ikke var lige så belastet.

Derefter havde et problem med, at applikationen var sat til at bruge localhost, så vi ikke kunne logge ind på selve applikationen fra en anden maskine. Det løste vi ved at rette indstillingerne i Rider. Derudover skulle vi have omlagt vores opsætning fra almindelig Docker til Docker Compose, da vi i første omgang kun havde enkelte Dockerfiles. Løsningen var en Compose-fil (docker-compose.yml), der får de to containere til at arbejde sammen. Til sidst skulle vi først lære at bruge en virtuel maskine med Docker. Vi løste det ved at søge information på nettet via Google samt få hjælp af AI til forståelse af teori og problemer. Dette hjalp os hen mod en løsning til noget vi føler har været rigtig kompliceret

---

# Reflektion

## Hvordan er security og infrastructure bundet sammen?

## Hvilke tekniske udfordringer har I stødt på?

## Hvad har i lært omkring deployment af en applikation på en server?

## Hvad ville I gøre anderledes hvis opgaven skulle deployes i en virksomhed? 

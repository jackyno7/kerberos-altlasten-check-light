# Kerberos-Altlasten-Check Light – typische Kerberos-Schwachstellen im Active Directory

Kostenloses PowerShell-Skript: prüft Kerberos-Einstellungen, Delegierung und Altlasten im Active Directory in **5 Punkten** und erzeugt einen übersichtlichen **HTML-Bericht auf Deutsch oder Englisch** (`-Language de|en`, Standard je nach Windows-Sprache). Es arbeitet **ausschließlich lesend**: Es ändert nichts, legt nichts an und überträgt keine Daten.

![Beispielbericht](Beispielbericht.png)

Der gezeigte Bericht stammt aus einer Testdomäne. Das vollständige Beispiel liegt als [Beispielbericht.html](Beispielbericht.html) bei.

## Was geprüft wird

| Nr. | Bereich | Prüfpunkt |
|---|---|---|
| K1 | Kerberos | Kennwort des Kontos krbtgt älter als 180 Tage |
| K4 | Kerberos | Kerberos-Vorauthentifizierung abgeschaltet |
| K10 | Altlasten | Konten mit adminCount ohne Administratorgruppe |
| K11 | Altlasten | Jeder Benutzer darf Computerkonten anlegen |
| K14 | Altlasten | Konten mit SID-Verlauf (SIDHistory) |

Jeder Befund kommt mit Erklärung und Empfehlung.

## Start

```powershell
powershell -ExecutionPolicy Bypass -File .\Kerberos-Altlasten-Check-Light.ps1
```

Alle Optionen zeigt `Get-Help .\Kerberos-Altlasten-Check-Light.ps1 -Detailed`. Voraussetzungen und Rechte stehen im Kopf des Skripts. Getestet mit Windows Server 2019, 2022 und 2025 in Testdomänen (deutsches Windows).

## Vollversion

Die Light-Version enthält 5 von 26 Prüfpunkten (19 %). Die **Vollversion** prüft zusätzlich unter anderem:

- Privilegierte Konten mit Dienstprinzipalnamen (SPN)
- Dienstkonten mit SPN und Kennwort älter als N Tage
- Uneingeschränkte Delegierung außerhalb der Domänencontroller
- Eingeschränkte Delegierung mit Protokollübergang
- Ressourcenbasierte Delegierung eingerichtet
- Konten ohne AES-Verschlüsselung
- Privilegierte Konten, die delegiert werden dürfen
- Gruppe "Prä-Windows 2000 kompatibler Zugriff" enthält Jeder oder Anonymous
- Anonyme LDAP-Abfragen erlaubt
- Vorab angelegte Computerkonten ohne Kennwortpflicht
- Kennwörter in Gruppenrichtlinien (SYSVOL)
- SMBv1 auf Domänencontrollern aktiv
- SMB-Signierung nicht erzwungen
- LDAP-Signierung nicht erzwungen
- LDAP-Kanalbindung nicht immer erzwungen
- Domänencontroller nehmen NTLMv1 an
- LM-Hashwerte werden gespeichert
- Anonyme Zugriffe mit den Rechten von "Jeder"
- Druckwarteschlange läuft auf Domänencontrollern
- Kerberos-Verschlüsselung nicht auf AES beschränkt
- LDAP-Signierung unter Windows Server 2025 nicht ausdrücklich festgelegt

➜ **[Vollversion auf Gumroad](https://mueller86.gumroad.com/l/zptvct)** · **[Vollversion auf Etsy](https://www.etsy.com/listing/4593092377)** · **[alle Prüfskripte im Shop](https://www.etsy.com/shop/ITAdminToolsbyMM)**

## Weitere kostenlose Prüfskripte

- [AD-Schnellcheck](https://github.com/jackyno7/ad-schnellcheck) (8 Prüfpunkte zur Domäne)
- [Rechner Inventar Light](https://github.com/jackyno7/rechner-inventar-light)
- [Anmelde Sperrbericht Light](https://github.com/jackyno7/anmelde-sperrbericht-light)
- [Berechtigungsbericht Light](https://github.com/jackyno7/berechtigungsbericht-light)
- [Dateiserver Bericht Light](https://github.com/jackyno7/dateiserver-bericht-light)
- [GPO Bericht Light](https://github.com/jackyno7/gpo-bericht-light)
- [DNS DHCP Bericht Light](https://github.com/jackyno7/dns-dhcp-bericht-light)
- [DC Gesundheitsbericht Light](https://github.com/jackyno7/dc-gesundheitsbericht-light)

<!-- querverweis:anfang -->
## Alle Skripte und Vorlagen

Übersicht aller Prüfskripte und Vorlagen: **[github.com/jackyno7](https://github.com/jackyno7)**

Vollversionen:

- Active Directory Prüfbericht: [Etsy](https://www.etsy.com/listing/4588853943) · [Gumroad](https://mueller86.gumroad.com/l/fcneoc)
- Domänencontroller-Gesundheitsbericht: [Etsy](https://www.etsy.com/listing/4593087246) · [Gumroad](https://mueller86.gumroad.com/l/bseljr)
- DNS- und DHCP-Bericht: [Etsy](https://www.etsy.com/listing/4593096270) · [Gumroad](https://mueller86.gumroad.com/l/sthgh)
- Kerberos- und Altlasten-Check: [Etsy](https://www.etsy.com/listing/4593092377) · [Gumroad](https://mueller86.gumroad.com/l/zptvct)
- Berechtigungsbericht Active Directory: [Etsy](https://www.etsy.com/listing/4593113568) · [Gumroad](https://mueller86.gumroad.com/l/xyjmdr)
- GPO-Bericht: [Etsy](https://www.etsy.com/listing/4593129111) · [Gumroad](https://mueller86.gumroad.com/l/wdosl)
- Anmelde- und Sperrbericht: [Etsy](https://www.etsy.com/listing/4593157082) · [Gumroad](https://mueller86.gumroad.com/l/ztktaaq)
- Rechner-Inventar aus Active Directory: [Etsy](https://www.etsy.com/listing/4593088535) · [Gumroad](https://mueller86.gumroad.com/l/zzycdd)
- Dateiserver-Bericht: [Etsy](https://www.etsy.com/listing/4612420692) · [Gumroad](https://mueller86.gumroad.com/l/wbbwj)
- Windows-Rechnerbericht: [Etsy](https://www.etsy.com/listing/4616020701) · [Gumroad](https://mueller86.gumroad.com/l/wmhfk)
- Exchange-Postfachbericht: [Etsy](https://www.etsy.com/listing/4614916333) · [Gumroad](https://mueller86.gumroad.com/l/gkdllj)
- Exchange-Kalenderrechte-Bericht: [Etsy](https://www.etsy.com/listing/4614799790) · [Gumroad](https://mueller86.gumroad.com/l/iabfb)
- Exchange-Nachrichtenverfolgung: [Etsy](https://www.etsy.com/listing/4614785975) · [Gumroad](https://mueller86.gumroad.com/l/msria)
- Active Directory Prüfskript-Paket: [Etsy](https://www.etsy.com/listing/4611942401) · [Gumroad](https://mueller86.gumroad.com/l/awzjtc)

Vorlagen und Checklisten (Notfallplan, Backup, Passwortrichtlinie, Onboarding, Homeoffice, Netzwerk-Dokumentation): [Etsy](https://www.etsy.com/shop/ITAdminToolsbyMM) · [Gumroad](https://mueller86.gumroad.com)
<!-- querverweis:ende -->

## Hinweise

- Der Bericht enthält Konto-, Rechner- oder Servernamen – bitte vertraulich behandeln.
- Der Bericht zeigt Auffälligkeiten anhand fester Regeln. Er ersetzt keine Sicherheitsprüfung und erhebt keinen Anspruch auf Vollständigkeit.
- Nutzung auf eigene Verantwortung, siehe [LICENSE](LICENSE).
- Bei der Ausarbeitung wurden KI-Werkzeuge unterstützend eingesetzt; Inhalte und Skript wurden fachlich geprüft und im Testlab getestet.

---

### English

Free, read-only PowerShell script that checks Kerberos settings, delegation and legacy leftovers in Active Directory (5 checks, HTML report in German or English (`-Language de|en`) with findings and recommendations). No changes are made and no data leaves the machine. Run: `powershell -ExecutionPolicy Bypass -File .\Kerberos-Altlasten-Check-Light.ps1`. The full version with 26 checks: https://mueller86.gumroad.com/l/zptvct

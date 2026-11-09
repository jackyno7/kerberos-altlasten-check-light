#Requires -Version 5.1
<#
.SYNOPSIS
    LIGHT-VERSION (5 von 26 Prüfpunkten, kostenlos). Kerberos- und Altlasten-Check: prüft ein Active Directory und seine Domänencontroller auf Einstellungen,
    die bekannte Angriffe erleichtern - Delegierung, angreifbare Dienstkonten, schwache Verschlüsselung,
    alte Protokolle (SMBv1, NTLMv1, unsigniertes LDAP) - und erzeugt einen HTML-Bericht.

.DESCRIPTION
    Das Skript arbeitet ausschließlich LESEND. Es ändert nichts im Active Directory und nichts an den
    Domänencontrollern, fordert keine Tickets an, testet keine Kennwörter und überträgt keine Daten.
    Es schreibt genau eine HTML-Datei (und auf Wunsch CSV-Dateien) in den angegebenen Ausgabeordner.

    Die Light-Version prüft nur Konten und Verzeichnis und braucht dafür ein normales Domänenkonto.

.PARAMETER Ausgabe
    Pfad der HTML-Datei. Standard: Kerberos-Altlasten-Check_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER KennwortAlterTage
    Dienstkonten mit SPN werden gemeldet, wenn ihr Kennwort älter ist (Standard 365).

.PARAMETER Server
    Bestimmter Domänencontroller oder Domäne (optional).

.PARAMETER Anmeldung
    Anmeldedaten eines Domänenkontos (Get-Credential), falls das Skript nicht als Domänenbenutzer läuft.
    Dann zusätzlich -Server angeben.

.PARAMETER Csv
    Schreibt zusätzlich je Prüfpunkt mit Treffern eine CSV-Datei neben den Bericht.

.PARAMETER NichtOeffnen
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Kerberos-Altlasten-Check.ps1

.EXAMPLE
    .\Kerberos-Altlasten-Check-Light.ps1 -Csv -Ausgabe C:\Berichte\kerberos.html

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Sicherheitsprüfung oder einen Penetrationstest. Nutzung auf eigene Verantwortung.
#>
[CmdletBinding()]
param(
    [string]$Ausgabe,
    [ValidateRange(1, 3650)][int]$KennwortAlterTage = 365,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [switch]$NichtOeffnen,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$Version = '1.0'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'Das PowerShell-Modul "ActiveDirectory" fehlt.' -ForegroundColor Red
    Write-Host 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.'
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = 'nie') { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy') } else { $leer } }
function JaNein($b) { if ($b) { 'Ja' } else { 'Nein' } }
function Ort($dn) { ($dn -replace '^(CN|OU)=.+?(?<!\\),', '') -replace ',DC=.*$', '' }
function Html($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }
function Kurz($t, $n = 220) { $t = ([string]$t -replace '\s+', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) + ' ...' } else { $t } }

# CSV-Dateien öffnen sich in Excel: Werte, die mit = + - @ beginnen, würden dort als Formel ausgeführt (Namen von Dateien, Ordnern, Konten oder Computern
# stammen von Benutzern). Diese Funktion ersetzt für dieses Skript den Befehl Export-Csv und setzt vor solche Werte ein Hochkomma.
function Export-Csv {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [Parameter(Mandatory)][string]$Path, [switch]$NoTypeInformation, [string]$Delimiter = ';', [string]$Encoding = 'UTF8')
    begin { $alle = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $alle.Add($InputObject) } }
    end {
        $sicher = foreach ($o in $alle) {
            $n = [ordered]@{}
            foreach ($p in $o.PSObject.Properties) { $v = $p.Value; if (($v -is [string]) -and ($v -match '^[=+@\t\r]|^-.')) { $v = "'" + $v }; $n[$p.Name] = $v }
            [pscustomobject]$n
        }
        $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -lt 2) { return $liste }
    $namen = New-Object System.Collections.Generic.List[string]
    foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
    if ($namen.Count -eq @($liste[0].PSObject.Properties.Name).Count) { return $liste }
    @($liste | Select-Object -Property $namen)
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *')
}

# Besteht ein Prüfpunkt nur aus Platzhalterzeilen (Abfrage fehlgeschlagen), ist das kein Mangel dieses Prüfpunkts: als Info führen statt
# mit seiner Stufe, damit es in den Kacheln nicht als hoher Befund zählt. Nur für Prüfpunkte, deren Ergebnis von einer Abfrage abhängt.
function InfoWennNurNichtGeprueft([string]$IdMuster) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster -and $_.Anzahl -gt 0 -and $_.Stufe -ne 'Info' })) {
        if (-not @($x.Objekte | Where-Object { -not (IstPlatzhalter $_) }).Count) { $x.Stufe = 'Info' }
    }
}

# Prüfpunkte, die für einzelne Server nicht ausgewertet werden konnten (Abfrage fehlgeschlagen), dürfen nicht als "ohne Befund" erscheinen:
# je Server eine Zeile "nicht geprüft" anhängen; hatte der Prüfpunkt sonst keinen Treffer, steht er als Info statt als OK.
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = 'Abfrage nicht möglich') {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = "Nicht geprüft - $Grund (siehe $Verweis)"; Details = '' } })
        $x.Objekte = @($x.Objekte) + $zeilen
        $x.Anzahl = $x.Objekte.Count
        if (-not $war) { $x.Stufe = 'Info' }
    }
}
function Befund {
    param([string]$Id, [string]$Bereich, [string]$Titel, [ValidateSet('Hoch', 'Mittel', 'Niedrig', 'Info')][string]$Stufe,
        $Objekte, [string]$Erklaerung, [string]$Empfehlung)
    $liste = @($Objekte | Where-Object { $null -ne $_ })
    $status = $Stufe
    if ($liste.Count -eq 0) { $status = 'OK' }
    $Befunde.Add([pscustomobject]@{
            Id = $Id; Bereich = $Bereich; Titel = $Titel; Stufe = $status; Anzahl = $liste.Count
            Objekte = $liste; Erklaerung = $Erklaerung; Empfehlung = $Empfehlung
        })
}

# Schreibt den HTML-Bericht (und auf Wunsch CSV-Dateien). $Abschnitte: Überschrift -> Objekte oder fertiges HTML,
# erscheinen vor den Befunden. $Anhang: Überschrift -> Text, erscheint am Ende unverändert.
function BerichtSchreiben {
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = 'Domäne', [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host '  Bericht schreiben ...'
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, $Bezug, $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

    $rang = @{ Hoch = 0; Mittel = 1; Niedrig = 2; Info = 3; OK = 4 }
    $zahl = @{}
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') { $zahl[$s] = @($Befunde | Where-Object Stufe -eq $s).Count }
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;color:#2b2f36;margin:0;background:#f4f6fa}
.seite{max-width:1100px;margin:0 auto;padding:28px 24px 60px}
h1{color:#1f5fae;margin:0 0 4px;font-size:28px} h2{color:#1f5fae;font-size:19px;margin:34px 0 10px;border-bottom:2px solid #d0d5dd;padding-bottom:6px}
.meta{color:#6b7280;font-size:13px;margin-bottom:22px}
.kacheln{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.kachel{flex:1;min-width:150px;background:#fff;border-radius:10px;padding:14px 18px;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.kachel b{display:block;font-size:30px} .kachel span{font-size:13px;color:#6b7280}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:8px 0 4px}
th{background:#1f5fae;color:#fff;text-align:left;padding:7px 9px;font-weight:600} td{padding:6px 9px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:break-word}
tr:nth-child(even) td{background:#f9fafb}
.marke{display:inline-block;min-width:58px;text-align:center;padding:2px 9px;border-radius:11px;color:#fff;font-size:12px;font-weight:600}
.m-Hoch{background:#d92d20}.m-Mittel{background:#f79009}.m-Niedrig{background:#ca8a04}.m-OK{background:#12b76a}.m-Info{background:#1f5fae}
.befund{background:#fff;border-radius:10px;padding:16px 20px;margin:14px 0;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.befund h3{margin:0 0 6px;font-size:16px} .befund p{margin:5px 0;font-size:14px;line-height:1.45} .befund .emp{color:#14532d}
.Hoch{border-color:#d92d20}.Mittel{border-color:#f79009}.Niedrig{border-color:#eab308}.OK{border-color:#12b76a}.Info{border-color:#1f5fae}
.klein{color:#6b7280;font-size:12px} a{color:#1f5fae;text-decoration:none}
pre{background:#fff;border:1px solid #d0d5dd;border-radius:8px;padding:12px 14px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.fuss{margin-top:40px;color:#6b7280;font-size:12px;border-top:1px solid #d0d5dd;padding-top:12px}
@media print{body{background:#fff}.befund,.kachel{box-shadow:none;border:1px solid #d0d5dd;border-left-width:8px;break-inside:avoid}}
'@
    $h = New-Object System.Text.StringBuilder
    [void]$h.Append("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · erstellt am $($jetzt.ToString('dd.MM.yyyy HH:mm')) von $(Html "$env:USERDOMAIN\$env:USERNAME") auf $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = 'Befunde mit hoher Priorität'; Mittel = 'mit mittlerer Priorität'; Niedrig = 'mit niedriger Priorität'; Info = 'Hinweise und nicht geprüft'; OK = 'Prüfpunkte ohne Befund' }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>Umgebung</h2><table><tr><th>Eigenschaft</th><th>Wert</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html $k)</td><td>$(Html $Umgebung[$k])</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>Übersicht der Prüfpunkte</h2><table><tr><th>Nr.</th><th>Bereich</th><th>Prüfpunkt</th><th>Treffer</th><th>Bewertung</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html $k)</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>Keine Einträge.</p>") }
    }

    [void]$h.Append("<h2>Befunde</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) Treffer)</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>Empfehlung:</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>Keine Auffälligkeiten gefunden.</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>Ohne Befund</h2><table><tr><th>Nr.</th><th>Prüfpunkt</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · Das Skript hat ausschließlich gelesen und nichts verändert. $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ("Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host "Bericht: $ziel"
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

function KontoZeile($o, [System.Collections.IDictionary]$Zusatz = @{}) {
    $typ = switch -Regex ("$($o.ObjectClass)") { 'msDS-GroupManagedServiceAccount' { 'Verwaltetes Dienstkonto'; break } 'computer' { 'Computer'; break } default { 'Benutzer' } }
    $z = [ordered]@{ Konto = $o.SamAccountName; Typ = $typ; Aktiv = JaNein $o.Enabled; 'Kennwort gesetzt' = Datum $o.PasswordLastSet; Ort = Ort $o.DistinguishedName }
    foreach ($k in $Zusatz.Keys) { $z[$k] = $Zusatz[$k] }
    [pscustomobject]$z
}
function DcZeile($dc, $was, $details = '') { [pscustomobject]@{ 'Domänencontroller' = $dc; Feststellung = $was; Details = $details } }
# Eine fehlgeschlagene Abfrage ist selbst eine Feststellung - sonst sähe der Prüfpunkt fälschlich sauber aus
function DcFehlzeile($dc, $fehler) { DcZeile $dc 'Abfrage fehlgeschlagen - nicht geprüft' (Kurz $fehler.Exception.Message) }

# ------------------------------------------------------------------ Daten lesen
Write-Host 'Kerberos- und Altlasten-Check - es wird nur gelesen, nichts verändert.' -ForegroundColor Cyan
$dom = Get-ADDomain @ad
$wald = Get-ADForest @ad
$dn = $dom.DistinguishedName
$sid = $dom.DomainSID.Value
$wurzel = Get-ADRootDSE @ad
$jetzt = Get-Date

Write-Host '  Konten ...'
$eig = 'Enabled', 'ServicePrincipalName', 'PasswordLastSet', 'DoesNotRequirePreAuth', 'TrustedForDelegation', 'TrustedToAuthForDelegation',
'msDS-AllowedToDelegateTo', 'PrincipalsAllowedToDelegateToAccount', 'UseDESKeyOnly', 'msDS-SupportedEncryptionTypes', 'AccountNotDelegated',
'adminCount', 'SIDHistory', 'PasswordNotRequired', 'LastLogonDate', 'primaryGroupID', 'whenCreated'
$benutzer = @(Get-ADUser -Filter * -Properties $eig @ad)
$computer = @(Get-ADComputer -Filter * -Properties $eig @ad)
$dienst = @()
try { $dienst = @(Get-ADServiceAccount -Filter * -Properties $eig @ad) } catch { }
$alle = $benutzer + $computer + $dienst
$krbtgt = $benutzer | Where-Object { $_.SID.Value -eq "$sid-502" }
$personen = @($benutzer | Where-Object { $_.SID.Value -notmatch '-(501|502|503)$' })
$dcKonten = @($computer | Where-Object { $_.primaryGroupID -in 516, 521 })

Write-Host '  Privilegierte Gruppen ...'
$privSids = "$sid-512", "$sid-519", "$sid-518", 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-551'
$privVon = @{}
$privGruppenDn = @()
foreach ($s in $privSids) {
    try { $g = Get-ADGroup -Identity $s @ad } catch { continue }
    $privGruppenDn += $g.DistinguishedName
    foreach ($t in @(Get-ADUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$($g.DistinguishedName))" @ad)) {
        if (-not $privVon.ContainsKey($t.SamAccountName)) { $privVon[$t.SamAccountName] = New-Object System.Collections.Generic.List[string] }
        $privVon[$t.SamAccountName].Add($g.Name)
    }
}
$geschuetzt = @{}
try {
    $pu = Get-ADGroup -Identity "$sid-525" @ad
    Get-ADUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$($pu.DistinguishedName))" @ad | ForEach-Object { $geschuetzt[$_.SamAccountName] = $true }
} catch { }

# ------------------------------------------------------------------ Teil 1: Kerberos und Konten
Write-Host '  Auswertung Konten ...'
$k = @()
if ($krbtgt -and $krbtgt.PasswordLastSet -lt $jetzt.AddDays(-180)) {
    $k = [pscustomobject]@{ Konto = 'krbtgt'; 'Kennwort gesetzt' = Datum $krbtgt.PasswordLastSet; 'Alter in Tagen' = [int]($jetzt - $krbtgt.PasswordLastSet).TotalDays }
}
Befund 'K1' 'Kerberos' 'Kennwort des Kontos krbtgt älter als 180 Tage' 'Mittel' $k `
    'Mit dem Kennwort des Kontos krbtgt werden alle Kerberos-Tickets der Domäne signiert. Wer es einmal erbeutet hat, kann sich beliebige Tickets ausstellen (Golden Ticket), bis es zweimal geändert wurde.' `
    'Kennwort regelmäßig zweimal im Abstand von mindestens 10 Stunden zurücksetzen (Anleitung und Skript von Microsoft beachten).'

Befund 'K4' 'Kerberos' 'Kerberos-Vorauthentifizierung abgeschaltet' 'Hoch' `
($alle | Where-Object { $_.DoesNotRequirePreAuth } | ForEach-Object { KontoZeile $_ }) `
    'Für diese Konten kann jeder im Netz ohne Anmeldung Daten abrufen, mit denen sich das Kennwort offline erraten lässt (AS-REP-Roasting).' `
    'Option "Keine Kerberos-Vorauthentifizierung erforderlich" entfernen.'

Befund 'K10' 'Altlasten' 'Konten mit adminCount ohne Administratorgruppe' 'Niedrig' `
($personen | Where-Object { $_.adminCount -eq 1 -and -not $privVon.ContainsKey($_.SamAccountName) } | ForEach-Object { KontoZeile $_ }) `
    'Diese Konten waren einmal Mitglied einer geschützten Gruppe. Die Markierung bleibt danach stehen - und mit ihr die abgeschaltete Vererbung der Berechtigungen, sodass delegierte Rechte (z. B. Kennwort zurücksetzen durch den Helpdesk) hier nicht wirken. Mitglieder weiterer geschützter Gruppen wie Druck-Operatoren erscheinen hier ebenfalls.' `
    'Attribut adminCount leeren und die Vererbung in den Sicherheitseinstellungen des Kontos wieder einschalten.'

$q = @()
$quote = (Get-ADObject -Identity $dn -Properties 'ms-DS-MachineAccountQuota' @ad).'ms-DS-MachineAccountQuota'
if ($quote -gt 0) { $q = [pscustomobject]@{ Einstellung = 'ms-DS-MachineAccountQuota'; Ist = $quote; Empfohlen = 0 } }
Befund 'K11' 'Altlasten' 'Jeder Benutzer darf Computerkonten anlegen' 'Mittel' $q `
    'In der Standardeinstellung darf jeder Domänenbenutzer bis zu 10 Computerkonten anlegen. Mehrere bekannte Angriffe auf Kerberos und die Delegierung setzen genau das voraus.' `
    'Wert am Domänenobjekt auf 0 setzen und die Aufnahme von Rechnern gezielt an die IT delegieren.'

Befund 'K14' 'Altlasten' 'Konten mit SID-Verlauf (SIDHistory)' 'Mittel' `
($alle | Where-Object { @($_.SIDHistory).Count } | ForEach-Object { KontoZeile $_ ([ordered]@{ 'SID-Verlauf' = (@($_.SIDHistory | ForEach-Object { "$_" }) -join ', ') }) }) `
    'Der SID-Verlauf stammt aus Migrationen: Das Konto besitzt zusätzlich die Rechte seiner alten Identität. Angreifer nutzen das Attribut, um sich unauffällig Rechte zu verschaffen - besonders heikel sind SIDs der eigenen Domäne oder von Administratorgruppen.' `
    'Nach Abschluss einer Migration den SID-Verlauf entfernen. Unerklärliche Einträge als Sicherheitsvorfall behandeln.'

# ------------------------------------------------------------------ Teil 2: Einstellungen der Domänencontroller
$dcListe = @()

# Abfragen, die fehlgeschlagen sind, zählen nicht als Mangel des jeweiligen Prüfpunkts
InfoWennNurNichtGeprueft '^[KL]\d+$'

# ------------------------------------------------------------------ Bericht
$umgebung = [ordered]@{
    'Domäne (NetBIOS)'                       = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    'Funktionsebene Domäne / Gesamtstruktur' = "$($dom.DomainMode) / $($wald.ForestMode)"
    'Benutzer / Computer / verwaltete Dienstkonten' = "$($benutzer.Count) / $($computer.Count) / $($dienst.Count)"
    'Privilegierte Konten'                   = $privVon.Count
    'Konten in "Protected Users"'            = $geschuetzt.Count
    'Kennwort krbtgt gesetzt am'             = Datum $krbtgt.PasswordLastSet
    'Prüfung der Domänencontroller'          = $(if ($true) { 'nicht Teil der Light-Version' } else { "$(@($dcListe | Where-Object Geprüft -eq 'Ja').Count) von $($dcListe.Count) geprüft" })
    'Schwellen dieses Berichts'              = "Kennwortalter für Dienstkonten ab $KennwortAlterTage Tagen"
}
$abschnitte = [ordered]@{}
BerichtSchreiben -Name 'Kerberos- und Altlasten-Check Light' -Datei 'Kerberos-Altlasten-Check' -Bezug $dom.DNSRoot -Umgebung $umgebung -Abschnitte $abschnitte `
    -Fuss 'Light-Version mit 5 von 26 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/zptvct). Der Bericht zeigt Auffälligkeiten anhand fester Regeln; er ersetzt keine Sicherheitsprüfung und keinen Penetrationstest und erhebt keinen Anspruch auf Vollständigkeit. Dieser Bericht enthält Kontonamen und sicherheitsrelevante Einstellungen - bitte vertraulich behandeln.' | Out-Null
if ($PassThru) { $Befunde }

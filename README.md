# Veridan scan

[English](#english) · [Nederlands](#nederlands)

## English

A read-only PowerShell script that reads the configuration of a Microsoft 365 tenant and writes one JSON file with counts. It is the free scan behind [cbwbewijs.nl](https://cbwbewijs.nl) and [veridan.eu/scan](https://veridan.eu/scan/).

### What it does

- Free mode (the default) runs on your own computer, with your own sign-in and delegated **read** permissions only.
- It writes `collections\veridan-scan-<yyyyMMdd-HHmmss>.json` next to the script, plus a `.sha256` file for that output.
- The Free file contains counts only: no user, group or service principal objects, no names, no email addresses, no tenant ID. [`examples/`](examples/) has a Free file from our own lab tenant.
- It changes nothing in your tenant. It signs in with `-ContextScope Process` and calls `Disconnect-MgGraph` at the end, so no token stays cached in your profile.
- It sends nothing. Uploading the file to Veridan is a separate step that you choose.

### Requirements

- PowerShell 7 (`pwsh`)
- The Microsoft Graph authentication module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
- An account with at least **Global Reader**. Without it, sign-in activity and the MFA registration report cannot be read and the file records them as unknown.
- If the permissions below have not been granted in your tenant before, an administrator who may grant admin consent approves them at sign-in.

### Permissions (all read)

`Directory.Read.All` · `Policy.Read.All` · `AuditLog.Read.All` · `Application.Read.All` · `Reports.Read.All` · `RoleManagement.Read.Directory` · `DeviceManagementConfiguration.Read.All` · `Organization.Read.All`

### Run

```powershell
# 1. Check that the script is unchanged: compare with the SHA-256 in the release notes
Get-FileHash .\Invoke-VeridanCollection.ps1 -Algorithm SHA256

# 2. The script is not code-signed yet; after the check, unblock it
Unblock-File .\Invoke-VeridanCollection.ps1

# 3. Run the free scan
.\Invoke-VeridanCollection.ps1 -Mode Free -TenantId <your-tenant-id>
```

Without `-TenantId` the script uses the default tenant of the signed-in account and warns you.

### Full mode

The same script has a Full mode (`-Mode Full`). It needs an app registration with a certificate and is used only in a paid engagement, under a contract and a data processing agreement. You do not need it for the free scan. With `-IncludeScubaGear`, Full mode calls [ScubaGear](https://github.com/cisagov/ScubaGear) if it is installed; ScubaGear is not part of this repository.

### Not in this repository

Veridan's rules, framework mappings, scoring and dossier templates.

### Licence and contact

MIT, see [LICENSE](LICENSE). Veridan is a trade name of Intelligence EOOD, Bulgaria. Questions: [info@veridan.eu](mailto:info@veridan.eu).

## Nederlands

Een PowerShell-script dat alleen leest: het leest de configuratie van een Microsoft 365-tenant en schrijft één JSON-bestand met getallen. Het is de gratis scan achter [cbwbewijs.nl](https://cbwbewijs.nl) en [veridan.eu/nl/scan](https://veridan.eu/nl/scan/).

### Wat het doet

- De Free-modus (standaard) draait op je eigen computer, met je eigen aanmelding en alleen gedelegeerde **lees**rechten.
- Het script schrijft `collections\veridan-scan-<yyyyMMdd-HHmmss>.json` naast het script, plus een `.sha256`-bestand voor die uitvoer.
- Het Free-bestand bevat alleen getallen: geen gebruikers-, groeps- of service-principal-objecten, geen namen, geen e-mailadressen, geen tenant-ID. In [`examples/`](examples/) staat een Free-bestand uit onze eigen labtenant.
- Het wijzigt niets in je tenant. Het meldt zich aan met `-ContextScope Process` en roept aan het eind `Disconnect-MgGraph` aan, zodat er geen token in je profiel achterblijft.
- Het verstuurt niets. Het bestand naar Veridan uploaden is een aparte stap waar je zelf voor kiest.

### Vereisten

- PowerShell 7 (`pwsh`)
- De Microsoft Graph-authenticatiemodule: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
- Een account met minimaal **Global Reader**. Zonder die rol zijn aanmeldactiviteit en het MFA-registratierapport niet te lezen; het bestand vermeldt ze dan als onbekend.
- Zijn de onderstaande rechten in je tenant nog niet eerder toegekend, dan keurt een beheerder die beheerderstoestemming mag geven ze goed bij het aanmelden.

### Rechten (allemaal lezen)

`Directory.Read.All` · `Policy.Read.All` · `AuditLog.Read.All` · `Application.Read.All` · `Reports.Read.All` · `RoleManagement.Read.Directory` · `DeviceManagementConfiguration.Read.All` · `Organization.Read.All`

### Uitvoeren

```powershell
# 1. Controleer of het script ongewijzigd is: vergelijk met de SHA-256 in de release notes
Get-FileHash .\Invoke-VeridanCollection.ps1 -Algorithm SHA256

# 2. Het script is nog niet ondertekend met een codecertificaat; deblokkeer het na de controle
Unblock-File .\Invoke-VeridanCollection.ps1

# 3. Voer de gratis scan uit
.\Invoke-VeridanCollection.ps1 -Mode Free -TenantId <jouw-tenant-id>
```

Zonder `-TenantId` gebruikt het script de standaardtenant van het aangemelde account en waarschuwt het je.

### Full-modus

Hetzelfde script heeft een Full-modus (`-Mode Full`). Die heeft een app-registratie met een certificaat nodig en wordt alleen gebruikt bij een betaalde opdracht, met een overeenkomst en een verwerkersovereenkomst. Voor de gratis scan heb je hem niet nodig. Met `-IncludeScubaGear` roept de Full-modus [ScubaGear](https://github.com/cisagov/ScubaGear) aan als het geïnstalleerd is; ScubaGear zit niet in deze repository.

### Niet in deze repository

De regels, de koppeling aan wettelijke kaders, de scoreberekening en de dossiersjablonen van Veridan.

### Licentie en contact

MIT, zie [LICENSE](LICENSE). Veridan is een handelsnaam van Intelligence EOOD, Bulgarije. Vragen: [info@veridan.eu](mailto:info@veridan.eu).

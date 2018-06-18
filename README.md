# RainDance
> A toolkit for enumerating and collecting information from Office 365

## Description

Raindance uses built-in powershell modules, namely from the MSOnline & AzureAD powershell modules to log into Office 365 tenants with
legitimate credentials and pulls out the list of users, their mailing groups and distros, roles/permissions, and identify administrators
in the tenant. This tool is intended to be used as an attack tool to assist penetration testers in enumerating users and select targets
for offensive engagements.

## Features
* Enumerates domain information within O365
* Get the full list of users, including disabled accounts
* Get a list of the mailing/distribution groups in the tenant
* Identify administrative users and highlight Global Administrators (Company Admins)

### In the works
* Support for Exchange Server & Office API login
* Search and download emails (with administrator impersonation)
* Automated password searcher (dig through mail & sharepoint for indicators of plaintext passwords)
* Upload/Download files to/from Sharepoint
* Malicious modification of Sharepoint/OneDrive files

## Installation & Running
Raindance runs like a powershell module, and does not require any installation. Simply clone it to a directory, and import as a
powershell module to gain access to its functions. It is recommended to run as administrator the first time in order to enable
it to install the necessary dependencies, or you may do so manually.

`# From a Powershell Command Window... `
`git clone https://github.com/true-demon/raindance.git C:\Path\to\Raindance`
`cd C:\Path\to\Raindance`
`Import-Module .\raindance.ps1`

```

```

### Dependencies
* Windows Only (for now): Microsoft has promised to (eventually) add Linux support for the library dependencies.
* Powershell v5.0+: This is due to .NET dependencies
* Library - MSOnline: Download using powershell `Install-Module msonline`
* Library - AzureAD: Download using powershell `Install-Module AzureAD`

### Optional
It is recommended to install [chocolatey](https://chocolatey.org/install "Chocolatey Installer") for windows to assist with installing Powershell packages


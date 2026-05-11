## Monologue-pwn

`Monologue-pwn.ps1` runs an **Internal Monologue** style NTLM capture technique on Windows.

It enables collection of Net-NTLM material without dumping LSASS.

## How it works
1. The script compiles embedded C# in memory (`Add-Type`).
2. The C# calls SSPI/NTLM APIs (`AcquireCredentialsHandle`, `InitializeSecurityContext`) to generate NTLM authentication messages for a selected challenge.
3. The script parses NTLM response fields (user, domain, LM/NT response data).
4. When elevated and impersonation is enabled, it enumerates accessible process/thread tokens and runs once per SID.
5. If downgrade mode is enabled, it temporarily weakens local NTLM client settings and can restore them after execution.

## Parameters
- `-NoDowngrade` (default: disabled)
  - If set, **skips** temporary NTLM downgrade.
  - By default, downgrade is attempted and sets:
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LMCompatibilityLevel`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic`
- `-NoRestore` (default: disabled)
  - If set, **skips** restoring original registry values after downgrade.
- `-NoImpersonate` (default: disabled)
  - If set, runs only in the current security context.
- `-VerboseFlag` (default: disabled)
  - Shows additional runtime details, including impersonated user context names.
- `-Challenge` (default: `1122334455667788`)
  - 16 hex chars (8-byte challenge).
- `-AddDomainUser` (default: disabled)
  - Attempts to create a random domain user and add it to **Domain Admins** (requires sufficient AD privileges).
  - This mode runs in place of NTLM hash output logic for that execution path.

## Output
- NTLMv1-like:
  - `USER::DOMAIN:LMRESP:NTRESP:CHALLENGE`
- NTLMv2-like:
  - `USER::DOMAIN:CHALLENGE:NTLMv2_RESPONSE:NTLMv2_BLOB`
- `-AddDomainUser` mode:
  - Success/failure status text for AD user creation and group membership operations.

## Usage
### Default run
```powershell
.\Monologue-pwn.ps1

```

### Current user only (no impersonation, no downgrade)
```powershell
.\Monologue-pwn.ps1 -NoImpersonate -NoDowngrade
```

### Custom challenge
```powershell
.\Monologue-pwn.ps1 -Challenge A1B2C3D4E5F60718
```

### Verbose execution
```powershell
.\Monologue-pwn.ps1 -VerboseFlag
```

### Attempt domain user + Domain Admins add
```powershell
.\Monologue-pwn.ps1 -AddDomainUser -VerboseFlag
```

## Requirements
- Windows + PowerShell
- .NET support for `Add-Type`
- Admin rights for full impersonation/downgrade behavior
- Domain privileges for `-AddDomainUser`

## Safety notes
- Downgrade mode modifies security-relevant registry values unless `-NoDowngrade` is specified.
- `-AddDomainUser` performs high-impact Active Directory account and group changes.
- Use only with explicit authorization

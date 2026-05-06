## What this is
`Invoke-InternalMonologue.ps1` runs an **Internal Monologue** style NTLM capture technique on Windows.

Enables the collection of Net-NTLM hashes without touching LSASS. Tested against both Windows Defender and an industry leading EDR with no detection as of 5/5/2026

## How the attack works
1. The script compiles embedded C# in memory (`Add-Type`).
2. That C# calls SSPI/NTLM APIs (`AcquireCredentialsHandle`, `InitializeSecurityContext`) to generate NTLM auth messages for a chosen challenge.
3. The script parses the NTLM response fields (user, domain, LM/NT response data).
4. If running as admin with impersonation enabled, it tries accessible process/thread tokens and repeats once per SID.
5. It can temporarily weaken local NTLM client settings to make response generation easier, then restore them.

## Parameters
- `-Downgrade` (default: `$true`)
  - Temporarily sets:
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LMCompatibilityLevel`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec`
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic`
- `-Restore` (default: `$true`)
  - Restores original values if downgrade was used.
- `-Impersonate` (default: `$true`)
  - When elevated, attempts token impersonation across processes/threads.
- `-VerboseFlag` (default: `$false`)
  - Prints impersonated user context names.
- `-Challenge` (default: `1122334455667788`)
  - 16 hex chars (8-byte challenge).

## Output
- NTLMv1-like:
  - `USER::DOMAIN:LMRESP:NTRESP:CHALLENGE`
- NTLMv2-like:
  - `USER::DOMAIN:CHALLENGE:NTLMv2_RESPONSE:NTLMv2_BLOB`

## How to use
> The script ends with `Invoke-InternalMonologue @PSBoundParameters`, so run it directly with parameters.

### Default run
```powershell
.\Invoke-InternalMonologue.ps1
```

### Current user only (no impersonation, no downgrade)
```powershell
.\Invoke-InternalMonologue.ps1 -Impersonate:$false -Downgrade:$false
```

### Custom challenge
```powershell
.\Invoke-InternalMonologue.ps1 -Challenge A1B2C3D4E5F60718
```

### Verbose impersonation
```powershell
.\Invoke-InternalMonologue.ps1 -VerboseFlag:$true
```

## Requirements
- Windows + PowerShell
- .NET support for `Add-Type`
- Admin rights for full impersonation/downgrade behavior

## Safety notes
- This modifies security-relevant registry values when `-Downgrade` is enabled.
- Run only with explicit authorization and change control.
- Prefer `-Restore:$true` to reduce lingering risk.

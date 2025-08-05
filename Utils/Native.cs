#nullable enable
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Exec;

/// <summary>
/// Contains native Windows API imports and structures for process execution and privilege management.
/// </summary>
public static class Native
{
    #region Native API Imports

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SaferCreateLevel(uint dwScopeId, uint dwLevelId, uint OpenFlags, out IntPtr pLevelHandle, IntPtr lpReserved);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SaferComputeTokenFromLevel(IntPtr LevelHandle, IntPtr InAccessToken, out IntPtr OutAccessToken, uint dwFlags, IntPtr lpReserved);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SaferCloseLevel(IntPtr hLevelHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LocalFree(IntPtr hMem);

    #endregion

    #region Structures

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    #endregion

    #region Constants

    public static class SaferConstants
    {
        public const uint SAFER_SCOPEID_USER = 1;
        public const uint SAFER_LEVELID_NORMALUSER = 0x2000;
        public const uint SAFER_LEVEL_OPEN = 1;
    }

    public static class TokenConstants
    {
        public const uint TOKEN_INTEGRITY_LEVEL = 25;
        public const uint SE_GROUP_INTEGRITY = 0x00000020;
    }

    public static class StartupInfoFlags
    {
        public const uint STARTF_USESHOWWINDOW = 0x00000001;
    }

    public static class ShowWindowCommands
    {
        public const ushort SW_HIDE = 0;
        public const ushort SW_SHOWNORMAL = 1;
    }

    #endregion
} 
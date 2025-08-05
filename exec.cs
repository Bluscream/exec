using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace exec
{
    class Program
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
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
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private const uint SecurityImpersonation = 2;
        private const uint TokenPrimary = 1;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint NORMAL_PRIORITY_CLASS = 0x00000020;

        private static bool IsRunningAsAdministrator()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static Process StartProcessAsUser(string fileName, string arguments)
        {
            if (!IsRunningAsAdministrator())
            {
                // If not running as admin, just use normal Process.Start
                var startInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false
                };
                return Process.Start(startInfo);
            }

            // Get the current process token
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY | TOKEN_DUPLICATE, out IntPtr hToken))
            {
                throw new InvalidOperationException("Failed to open process token");
            }

            try
            {
                // Duplicate the token
                if (!DuplicateTokenEx(hToken, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out IntPtr hNewToken))
                {
                    throw new InvalidOperationException("Failed to duplicate token");
                }

                try
                {
                    // Create startup info
                    var startupInfo = new STARTUPINFO
                    {
                        cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO)),
                        dwFlags = 0x00000001, // STARTF_USESHOWWINDOW
                        wShowWindow = 1 // SW_SHOWNORMAL
                    };

                    // Create process as user
                    if (!CreateProcessAsUser(hNewToken, fileName, arguments, IntPtr.Zero, IntPtr.Zero, false, CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS, IntPtr.Zero, null, ref startupInfo, out PROCESS_INFORMATION processInfo))
                    {
                        throw new InvalidOperationException("Failed to create process as user");
                    }

                    try
                    {
                        // Return a Process object for the created process
                        return Process.GetProcessById((int)processInfo.dwProcessId);
                    }
                    finally
                    {
                        CloseHandle(processInfo.hProcess);
                        CloseHandle(processInfo.hThread);
                    }
                }
                finally
                {
                    CloseHandle(hNewToken);
                }
            }
            finally
            {
                CloseHandle(hToken);
            }
        }

        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length == 0)
                return 1;

            bool waitForExit = false;
            bool runAsAdmin = false;
            bool runAsUser = false;
            string[] commandArgs = args;

            // Check for /wait flag
            if (args.Contains("/wait"))
            {
                waitForExit = true;
                commandArgs = commandArgs.Where(arg => arg != "/wait").ToArray();
                
                if (commandArgs.Length == 0)
                    return 1;
            }

            // Check for /admin flag
            if (commandArgs.Contains("/admin"))
            {
                runAsAdmin = true;
                commandArgs = commandArgs.Where(arg => arg != "/admin").ToArray();
                
                if (commandArgs.Length == 0)
                    return 1;
            }

            // Check for /user flag
            if (commandArgs.Contains("/user"))
            {
                runAsUser = true;
                commandArgs = commandArgs.Where(arg => arg != "/user").ToArray();
                
                if (commandArgs.Length == 0)
                    return 1;
            }

            // Validate that both /admin and /user are not specified
            if (runAsAdmin && runAsUser)
            {
                Console.Error.WriteLine("Error: Cannot specify both /admin and /user flags");
                return 1;
            }

            try
            {
                if (waitForExit)
                {
                    Process process = null;

                    if (runAsUser)
                    {
                        // Force run as user (non-elevated)
                        string fileName = commandArgs[0];
                        string arguments = string.Join(" ", commandArgs.Skip(1));
                        process = StartProcessAsUser(fileName, arguments);
                    }
                    else
                    {
                        // Normal execution
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = commandArgs[0],
                            Arguments = string.Join(" ", commandArgs.Skip(1)),
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        };

                        // Set verb for admin execution
                        if (runAsAdmin)
                        {
                            startInfo.Verb = "runas";
                            startInfo.UseShellExecute = true;
                            startInfo.RedirectStandardOutput = false;
                            startInfo.RedirectStandardError = false;
                            startInfo.CreateNoWindow = false;
                        }

                        process = Process.Start(startInfo);
                    }

                    if (process != null)
                    {
                        // Read output asynchronously (only if not running as admin and not forced as user)
                        string output = "";
                        string error = "";
                        
                        if (!runAsAdmin && !runAsUser)
                        {
                            output = process.StandardOutput.ReadToEnd();
                            error = process.StandardError.ReadToEnd();
                        }
                        
                        // Wait for process to complete
                        process.WaitForExit();
                        
                        // Print output (only if not running as admin and not forced as user)
                        if (!runAsAdmin && !runAsUser)
                        {
                            if (!string.IsNullOrEmpty(output))
                                Console.Out.Write(output);
                            if (!string.IsNullOrEmpty(error))
                                Console.Error.Write(error);
                        }
                        
                        return process.ExitCode;
                    }
                    return 1;
                }
                else
                {
                    // Fire-and-forget mode
                    if (runAsUser)
                    {
                        // Force run as user (non-elevated)
                        string fileName = commandArgs[0];
                        string arguments = string.Join(" ", commandArgs.Skip(1));
                        StartProcessAsUser(fileName, arguments);
                    }
                    else
                    {
                        // Normal execution
                        string command = string.Join(" ", commandArgs);
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = command,
                            UseShellExecute = true,
                            WindowStyle = ProcessWindowStyle.Normal
                        };

                        // Set verb for admin execution
                        if (runAsAdmin)
                        {
                            startInfo.Verb = "runas";
                        }

                        Process.Start(startInfo);
                    }
                    return 0;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        }
    }
}
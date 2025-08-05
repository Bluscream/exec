#nullable enable
using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;

namespace exec
{
    /// <summary>
    /// Command-line utility for executing processes with various privilege levels and wait options.
    /// </summary>
    public class Program
    {
        #region Native API Imports and Structures

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

        #endregion

        #region Constants

        private static class TokenAccessRights
        {
            public const uint TOKEN_QUERY = 0x0008;
            public const uint TOKEN_DUPLICATE = 0x0002;
            public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
            public const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        }

        private static class TokenTypes
        {
            public const uint SecurityImpersonation = 2;
            public const uint TokenPrimary = 1;
        }

        private static class ProcessCreationFlags
        {
            public const uint CREATE_NEW_CONSOLE = 0x00000010;
            public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
        }

        private static class StartupInfoFlags
        {
            public const uint STARTF_USESHOWWINDOW = 0x00000001;
        }

        private static class ShowWindowCommands
        {
            public const ushort SW_SHOWNORMAL = 1;
        }

        private static class CommandLineFlags
        {
            public const string WaitFlag = "/wait";
            public const string AdminFlag = "/admin";
            public const string UserFlag = "/user";
        }

        #endregion

        #region Execution Options

        /// <summary>
        /// Represents the execution options for the process.
        /// </summary>
        private class ExecutionOptions
        {
            public bool WaitForExit { get; set; }
            public bool RunAsAdmin { get; set; }
            public bool RunAsUser { get; set; }
            public string[] CommandArguments { get; set; } = Array.Empty<string>();

            /// <summary>
            /// Validates the execution options.
            /// </summary>
            /// <returns>True if valid, false otherwise.</returns>
            public bool Validate()
            {
                if (CommandArguments.Length == 0)
                {
                    Console.Error.WriteLine("Error: No command specified");
                    return false;
                }

                if (RunAsAdmin && RunAsUser)
                {
                    Console.Error.WriteLine("Error: Cannot specify both /admin and /user flags");
                    return false;
                }

                return true;
            }
        }

        #endregion

        #region Utility Methods

        /// <summary>
        /// Checks if the current process is running with administrator privileges.
        /// </summary>
        /// <returns>True if running as administrator, false otherwise.</returns>
        private static bool IsRunningAsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// Parses command line arguments into execution options.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        /// <returns>Parsed execution options.</returns>
        private static ExecutionOptions ParseArguments(string[] args)
        {
            var options = new ExecutionOptions();
            var remainingArgs = args.ToList();

            // Check for /wait flag
            if (remainingArgs.Contains(CommandLineFlags.WaitFlag))
            {
                options.WaitForExit = true;
                remainingArgs.Remove(CommandLineFlags.WaitFlag);
            }

            // Check for /admin flag
            if (remainingArgs.Contains(CommandLineFlags.AdminFlag))
            {
                options.RunAsAdmin = true;
                remainingArgs.Remove(CommandLineFlags.AdminFlag);
            }

            // Check for /user flag
            if (remainingArgs.Contains(CommandLineFlags.UserFlag))
            {
                options.RunAsUser = true;
                remainingArgs.Remove(CommandLineFlags.UserFlag);
            }

            options.CommandArguments = remainingArgs.ToArray();
            return options;
        }

        #endregion

        #region Process Execution Methods

        /// <summary>
        /// Starts a process with user privileges (non-elevated) using Windows API.
        /// </summary>
        /// <param name="fileName">The executable file name.</param>
        /// <param name="arguments">Command line arguments.</param>
        /// <returns>The started process.</returns>
        /// <exception cref="InvalidOperationException">Thrown when process creation fails.</exception>
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
                return Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start process");
            }

            // Get the current process token
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 
                TokenAccessRights.TOKEN_QUERY | TokenAccessRights.TOKEN_DUPLICATE, out IntPtr hToken))
            {
                throw new InvalidOperationException($"Failed to open process token. Error: {Marshal.GetLastWin32Error()}");
            }

            try
            {
                // Duplicate the token
                if (!DuplicateTokenEx(hToken, 
                    TokenAccessRights.TOKEN_ADJUST_DEFAULT | TokenAccessRights.TOKEN_ADJUST_SESSIONID, 
                    IntPtr.Zero, TokenTypes.SecurityImpersonation, TokenTypes.TokenPrimary, out IntPtr hNewToken))
                {
                    throw new InvalidOperationException($"Failed to duplicate token. Error: {Marshal.GetLastWin32Error()}");
                }

                try
                {
                    // Create startup info
                    var startupInfo = new STARTUPINFO
                    {
                        cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO)),
                        dwFlags = StartupInfoFlags.STARTF_USESHOWWINDOW,
                        wShowWindow = ShowWindowCommands.SW_SHOWNORMAL
                    };

                    // Create process as user
                    if (!CreateProcessAsUser(hNewToken, fileName, arguments, IntPtr.Zero, IntPtr.Zero, 
                        false, ProcessCreationFlags.CREATE_NEW_CONSOLE | ProcessCreationFlags.NORMAL_PRIORITY_CLASS, 
                        IntPtr.Zero, null, ref startupInfo, out PROCESS_INFORMATION processInfo))
                    {
                        throw new InvalidOperationException($"Failed to create process as user. Error: {Marshal.GetLastWin32Error()}");
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

        /// <summary>
        /// Executes a process in wait mode (synchronous execution).
        /// </summary>
        /// <param name="options">Execution options.</param>
        /// <returns>Exit code of the executed process.</returns>
        private static int ExecuteWithWait(ExecutionOptions options)
        {
            Process? process = null;

            try
            {
                if (options.RunAsUser)
                {
                    // Force run as user (non-elevated)
                    string fileName = options.CommandArguments[0];
                    string arguments = string.Join(" ", options.CommandArguments.Skip(1));
                    process = StartProcessAsUser(fileName, arguments);
                }
                else
                {
                    // Normal execution
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = options.CommandArguments[0],
                        Arguments = string.Join(" ", options.CommandArguments.Skip(1)),
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    // Set verb for admin execution
                    if (options.RunAsAdmin)
                    {
                        startInfo.Verb = "runas";
                        startInfo.UseShellExecute = true;
                        startInfo.RedirectStandardOutput = false;
                        startInfo.RedirectStandardError = false;
                        startInfo.CreateNoWindow = false;
                    }

                    process = Process.Start(startInfo);
                }

                if (process == null)
                {
                    Console.Error.WriteLine("Error: Failed to start process");
                    return 1;
                }

                // Read output asynchronously (only if not running as admin and not forced as user)
                string output = "";
                string error = "";
                
                if (!options.RunAsAdmin && !options.RunAsUser)
                {
                    output = process.StandardOutput.ReadToEnd();
                    error = process.StandardError.ReadToEnd();
                }
                
                // Wait for process to complete
                process.WaitForExit();
                
                // Print output (only if not running as admin and not forced as user)
                if (!options.RunAsAdmin && !options.RunAsUser)
                {
                    if (!string.IsNullOrEmpty(output))
                        Console.Out.Write(output);
                    if (!string.IsNullOrEmpty(error))
                        Console.Error.Write(error);
                }
                
                return process.ExitCode;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error executing process: {ex.Message}");
                return 1;
            }
        }

        /// <summary>
        /// Executes a process in fire-and-forget mode (asynchronous execution).
        /// </summary>
        /// <param name="options">Execution options.</param>
        /// <returns>0 on success, 1 on failure.</returns>
        private static int ExecuteFireAndForget(ExecutionOptions options)
        {
            try
            {
                if (options.RunAsUser)
                {
                    // Force run as user (non-elevated)
                    string fileName = options.CommandArguments[0];
                    string arguments = string.Join(" ", options.CommandArguments.Skip(1));
                    StartProcessAsUser(fileName, arguments);
                }
                else
                {
                    // Normal execution
                    string command = string.Join(" ", options.CommandArguments);
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = command,
                        UseShellExecute = true,
                        WindowStyle = ProcessWindowStyle.Normal
                    };

                    // Set verb for admin execution
                    if (options.RunAsAdmin)
                    {
                        startInfo.Verb = "runas";
                    }

                    Process.Start(startInfo);
                }
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error executing process: {ex.Message}");
                return 1;
            }
        }

        #endregion

        #region Main Entry Point

        /// <summary>
        /// Main entry point for the application.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        /// <returns>Exit code (0 for success, 1 for failure).</returns>
        [STAThread]
        public static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Error.WriteLine("Error: No arguments provided");
                return 1;
            }

            try
            {
                var options = ParseArguments(args);
                
                if (!options.Validate())
                {
                    return 1;
                }

                return options.WaitForExit 
                    ? ExecuteWithWait(options) 
                    : ExecuteFireAndForget(options);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Unexpected error: {ex.Message}");
                return 1;
            }
        }

        #endregion
    }
}
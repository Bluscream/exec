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
            public const ushort SW_HIDE = 0;
        }

        private static class CommandLineFlags
        {
            public const string WaitFlag = "/e:wait";
            public const string AdminFlag = "/e:admin";
            public const string UserFlag = "/e:user";
            public const string HiddenFlag = "/e:hidden";
            public const string HelpFlag = "/e:help";
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
            public bool RunHidden { get; set; }
            public bool ShowHelp { get; set; }
            public string[] CommandArguments { get; set; } = Array.Empty<string>();

            /// <summary>
            /// Validates the execution options.
            /// </summary>
            /// <returns>True if valid, false otherwise.</returns>
            public bool Validate()
            {
                if (ShowHelp)
                {
                    return true; // Help mode doesn't need command validation
                }

                if (CommandArguments.Length == 0)
                {
                    Console.Error.WriteLine("Error: No command specified");
                    return false;
                }

                if (RunAsAdmin && RunAsUser)
                {
                    Console.Error.WriteLine("Error: Cannot specify both /e:admin and /e:user flags");
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

            // Check for /e:wait flag
            if (remainingArgs.Contains(CommandLineFlags.WaitFlag))
            {
                options.WaitForExit = true;
                remainingArgs.Remove(CommandLineFlags.WaitFlag);
            }

            // Check for /e:admin flag
            if (remainingArgs.Contains(CommandLineFlags.AdminFlag))
            {
                options.RunAsAdmin = true;
                remainingArgs.Remove(CommandLineFlags.AdminFlag);
            }

            // Check for /e:user flag
            if (remainingArgs.Contains(CommandLineFlags.UserFlag))
            {
                options.RunAsUser = true;
                remainingArgs.Remove(CommandLineFlags.UserFlag);
            }

            // Check for /e:hidden flag
            if (remainingArgs.Contains(CommandLineFlags.HiddenFlag))
            {
                options.RunHidden = true;
                remainingArgs.Remove(CommandLineFlags.HiddenFlag);
            }

            // Check for /e:help flag
            if (remainingArgs.Contains(CommandLineFlags.HelpFlag))
            {
                options.ShowHelp = true;
                remainingArgs.Remove(CommandLineFlags.HelpFlag);
            }

            options.CommandArguments = remainingArgs.ToArray();
            return options;
        }

        #endregion

        #region Help Methods

        /// <summary>
        /// Displays help information about available command line arguments.
        /// </summary>
        private static void ShowHelp()
        {
            Console.WriteLine("exec - Command-line utility for executing processes with various privilege levels and wait options.");
            Console.WriteLine();
            Console.WriteLine("Usage: exec [options] <command> [arguments...]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  /e:help     Show this help message");
            Console.WriteLine("  /e:wait     Wait for the process to complete and return its exit code");
            Console.WriteLine("  /e:admin    Run the process with administrator privileges");
            Console.WriteLine("  /e:user     Force run the process with user privileges (non-elevated)");
            Console.WriteLine("  /e:hidden   Run the process with a hidden window");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  exec notepad.exe                    # Open Notepad");
            Console.WriteLine("  exec /e:wait cmd /c \"echo test\"     # Run command and wait for completion");
            Console.WriteLine("  exec /e:admin regedit.exe           # Run Registry Editor as admin");
            Console.WriteLine("  exec /e:user /e:hidden calc.exe     # Run Calculator as user with hidden window");
            Console.WriteLine("  exec /e:wait /e:admin cmd /c \"dir\" # Run dir command as admin and wait");
            Console.WriteLine();
            Console.WriteLine("Notes:");
            Console.WriteLine("  - /e:admin and /e:user are mutually exclusive");
            Console.WriteLine("  - /e:hidden can be combined with any other option");
            Console.WriteLine("  - When using /e:wait, output is captured and displayed (except for admin mode)");
            Console.WriteLine("  - The /e: prefix helps avoid conflicts with target application arguments");
        }

        #endregion

        #region Process Execution Methods

        /// <summary>
        /// Starts a process with user privileges (non-elevated) using Windows API.
        /// </summary>
        /// <param name="fileName">The executable file name.</param>
        /// <param name="arguments">Command line arguments.</param>
        /// <param name="hidden">Whether to run the process with a hidden window.</param>
        /// <returns>The started process.</returns>
        /// <exception cref="InvalidOperationException">Thrown when process creation fails.</exception>
        private static Process StartProcessAsUser(string fileName, string arguments, bool hidden = false)
        {
            // Always use normal Process.Start when not running as administrator
            // The /e:user flag is primarily useful when running as admin to force non-elevated execution
            if (!IsRunningAsAdministrator())
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    WindowStyle = hidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal
                };
                return Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start process");
            }

            // When running as admin, try a simpler approach first - use Process.Start with UseShellExecute
            // This often works better for GUI applications
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = true,
                    WindowStyle = hidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal
                };
                
                var process = Process.Start(startInfo);
                if (process != null)
                {
                    return process;
                }
            }
            catch (Exception)
            {
                // Fallback to Windows API method
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
                        wShowWindow = hidden ? ShowWindowCommands.SW_HIDE : ShowWindowCommands.SW_SHOWNORMAL
                    };
                    
                    // Create process as user - use different flags for better window creation
                    uint creationFlags = ProcessCreationFlags.NORMAL_PRIORITY_CLASS;
                    if (!hidden)
                    {
                        creationFlags |= ProcessCreationFlags.CREATE_NEW_CONSOLE;
                    }
                    
                    if (!CreateProcessAsUser(hNewToken, fileName, arguments, IntPtr.Zero, IntPtr.Zero, 
                        false, creationFlags, 
                        IntPtr.Zero, string.Empty, ref startupInfo, out PROCESS_INFORMATION processInfo))
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
                    
                    // For user mode, we need to handle output redirection differently
                    // since we can't redirect output when using CreateProcessAsUser
                    if (IsRunningAsAdministrator())
                    {
                        // When running as admin and forcing user mode, we can't redirect output
                        // So we'll just start the process and wait for it
                        process = StartProcessAsUser(fileName, arguments, options.RunHidden);
                    }
                    else
                    {
                        // When not running as admin, use normal Process.Start with output redirection
                        var startInfo = new ProcessStartInfo
                        {
                            FileName = fileName,
                            Arguments = arguments,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true,
                            WindowStyle = options.RunHidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal
                        };
                        process = Process.Start(startInfo);
                    }
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
                        CreateNoWindow = true,
                        WindowStyle = options.RunHidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal
                    };

                    // Set verb for admin execution
                    if (options.RunAsAdmin)
                    {
                        startInfo.Verb = "runas";
                        startInfo.UseShellExecute = true;
                        startInfo.RedirectStandardOutput = false;
                        startInfo.RedirectStandardError = false;
                        startInfo.CreateNoWindow = false;
                        startInfo.WindowStyle = options.RunHidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal;
                    }

                    process = Process.Start(startInfo);
                }

                if (process == null)
                {
                    Console.Error.WriteLine("Error: Failed to start process");
                    return 1;
                }

                // Read output asynchronously
                string output = "";
                string error = "";
                
                // Only try to read output if we have redirected it
                if (process.StartInfo.RedirectStandardOutput)
                {
                    output = process.StandardOutput.ReadToEnd();
                    error = process.StandardError.ReadToEnd();
                }
                
                // Wait for process to complete
                process.WaitForExit();
                
                // Print output if we captured it
                if (process.StartInfo.RedirectStandardOutput)
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
                    StartProcessAsUser(fileName, arguments, options.RunHidden);
                }
                else
                {
                    // Normal execution
                    string command = string.Join(" ", options.CommandArguments);
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = command,
                        UseShellExecute = true,
                        WindowStyle = options.RunHidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal
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
                ShowHelp();
                return 0;
            }

            try
            {
                var options = ParseArguments(args);
                
                if (options.ShowHelp)
                {
                    ShowHelp();
                    return 0;
                }
                
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
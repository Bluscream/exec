#nullable enable
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Runtime.InteropServices;

namespace Exec;

/// <summary>
/// Command-line utility for executing processes with various privilege levels and wait options.
/// </summary>
public class Program
{
    #region Constants

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
    /// Starts a process with user privileges (non-elevated) using WinSafer APIs.
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

        // When running as admin, use WinSafer APIs to create a limited token and start process
        IntPtr saferHandle = IntPtr.Zero;
        IntPtr psid = IntPtr.Zero;
        try
        {
            // 1. Create a new access token using WinSafer
            if (!Native.SaferCreateLevel(Native.SaferConstants.SAFER_SCOPEID_USER, Native.SaferConstants.SAFER_LEVELID_NORMALUSER, Native.SaferConstants.SAFER_LEVEL_OPEN, out saferHandle, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if (!Native.SaferComputeTokenFromLevel(saferHandle, IntPtr.Zero, out IntPtr newAccessToken, 0, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            // Set the token to medium integrity because SaferCreateLevel doesn't reduce the
            // integrity level of the token and keep it as high.
            if (!Native.ConvertStringSidToSid("S-1-16-8192", out psid))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            var tml = new Native.TOKEN_MANDATORY_LABEL
            {
                Label = new Native.SID_AND_ATTRIBUTES
                {
                    Sid = psid,
                    Attributes = Native.TokenConstants.SE_GROUP_INTEGRITY
                }
            };

            var length = (uint)Marshal.SizeOf(tml);
            var tmlPtr = Marshal.AllocHGlobal((int)length);
            try
            {
                Marshal.StructureToPtr(tml, tmlPtr, false);
                if (!Native.SetTokenInformation(newAccessToken, Native.TokenConstants.TOKEN_INTEGRITY_LEVEL, tmlPtr, length))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                Marshal.FreeHGlobal(tmlPtr);
            }

            // 2. Start process using the new access token
            var commandLine = $"{fileName} {arguments}".TrimEnd();
            var startupInfo = new Native.STARTUPINFO
            {
                cb = (uint)Marshal.SizeOf(typeof(Native.STARTUPINFO)),
                dwFlags = hidden ? Native.StartupInfoFlags.STARTF_USESHOWWINDOW : 0,
                wShowWindow = hidden ? Native.ShowWindowCommands.SW_HIDE : Native.ShowWindowCommands.SW_SHOWNORMAL
            };
            
            if (Native.CreateProcessAsUser(newAccessToken, string.Empty, commandLine, IntPtr.Zero, IntPtr.Zero, 
                false, 0, IntPtr.Zero, string.Empty, ref startupInfo, out Native.PROCESS_INFORMATION processInfo))
            {
                Native.CloseHandle(processInfo.hProcess);
                Native.CloseHandle(processInfo.hThread);
                return Process.GetProcessById((int)processInfo.dwProcessId);
            }
            else
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            if (saferHandle != IntPtr.Zero)
            {
                Native.SaferCloseLevel(saferHandle);
            }

            if (psid != IntPtr.Zero)
            {
                Native.LocalFree(psid);
            }
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
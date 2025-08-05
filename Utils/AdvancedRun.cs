#nullable enable
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Exec;
/// <summary>
/// Provides a clean interface for running applications with elevated privileges using AdvancedRun.exe
/// </summary>
public class AdvancedRun
{
    #region Properties

    /// <summary>
    /// The executable file to run
    /// </summary>
    public string? ExeFilename { get; set; }

    /// <summary>
    /// Command line arguments for the executable
    /// </summary>
    public string? CommandLine { get; set; }

    /// <summary>
    /// Starting directory for the process
    /// </summary>
    public string? StartDirectory { get; set; }

    /// <summary>
    /// Whether to wait for the process to exit (0 = no, 1 = yes)
    /// </summary>
    public bool WaitProcess { get; set; } = false;

    /// <summary>
    /// Process priority class (0-5, where 32 = Normal)
    /// </summary>
    public ProcessPriorityClass PriorityClass { get; set; } = ProcessPriorityClass.Normal;

    /// <summary>
    /// Window state for the application
    /// </summary>
    public AdvancedRunWindowState WindowState { get; set; } = AdvancedRunWindowState.Normal;

    /// <summary>
    /// Run as mode (5 = Run as current user while being admin)
    /// </summary>
    public AdvancedRunAsMode RunAs { get; set; } = AdvancedRunAsMode.CurrentUserAsAdmin;

    /// <summary>
    /// Process name to run as (e.g., "runtimebroker.exe")
    /// </summary>
    public string? RunAsProcessName { get; set; } = "runtimebroker.exe";

    /// <summary>
    /// Environment variables mode (1 = Use current environment)
    /// </summary>
    public AdvancedRunEnvironmentVariablesMode EnvironmentVariablesMode { get; set; } = AdvancedRunEnvironmentVariablesMode.UseCurrent;

    /// <summary>
    /// OS compatibility mode (0 = Disabled)
    /// </summary>
    public bool OSCompatMode { get; set; } = false;

    /// <summary>
    /// Whether to use search path (0 = no, 1 = yes)
    /// </summary>
    public bool UseSearchPath { get; set; } = false;

    /// <summary>
    /// Whether to parse variable command line (0 = no, 1 = yes)
    /// </summary>
    public bool ParseVarCommandLine { get; set; } = false;

    /// <summary>
    /// Run mode (1 = File, 2 = Command)
    /// </summary>
    public AdvancedRunMode RunMode { get; set; } = AdvancedRunMode.File;

    /// <summary>
    /// Command window mode (1 = Hidden)
    /// </summary>
    public AdvancedRunCommandWindowMode CommandWindowMode { get; set; } = AdvancedRunCommandWindowMode.Hidden;

    /// <summary>
    /// Path to AdvancedRun.exe (defaults to current directory)
    /// </summary>
    public string AdvancedRunPath { get; set; } = "AdvancedRun.exe";

    #endregion

    #region Enums

    /// <summary>
    /// Window state options
    /// </summary>
    public enum AdvancedRunWindowState
    {
        Normal = 1,
        Minimized = 2,
        Maximized = 3
    }

    /// <summary>
    /// Run as mode options
    /// </summary>
    public enum AdvancedRunAsMode
    {
        CurrentUser = 0,
        CurrentUserAsAdmin = 5,
        Admin = 1,
        TrustedInstaller = 2,
        System = 3,
        CurrentUserLimited = 4
    }

    /// <summary>
    /// Environment variables mode options
    /// </summary>
    public enum AdvancedRunEnvironmentVariablesMode
    {
        UseCurrent = 1,
        UseSystem = 2,
        UseCustom = 3
    }

    /// <summary>
    /// Run mode options
    /// </summary>
    public enum AdvancedRunMode
    {
        File = 1,
        Command = 2
    }

    /// <summary>
    /// Command window mode options
    /// </summary>
    public enum AdvancedRunCommandWindowMode
    {
        Hidden = 1,
        Visible = 0
    }

    #endregion

    #region Constructors

    /// <summary>
    /// Creates a new AdvancedRun instance with default settings
    /// </summary>
    public AdvancedRun() { }

    /// <summary>
    /// Creates a new AdvancedRun instance with the specified executable
    /// </summary>
    /// <param name="exeFilename">The executable file to run</param>
    public AdvancedRun(string exeFilename)
    {
        ExeFilename = exeFilename;
    }

    /// <summary>
    /// Creates a new AdvancedRun instance with the specified executable and command line
    /// </summary>
    /// <param name="exeFilename">The executable file to run</param>
    /// <param name="commandLine">Command line arguments</param>
    public AdvancedRun(string exeFilename, string commandLine)
    {
        ExeFilename = exeFilename;
        CommandLine = commandLine;
    }

    #endregion

    #region Public Methods

    /// <summary>
    /// Executes the application using AdvancedRun.exe
    /// </summary>
    /// <returns>The process that was started, or null if failed</returns>
    public Process? Execute()
    {
        // Validate based on RunMode
        if (RunMode == AdvancedRunMode.File && string.IsNullOrEmpty(ExeFilename))
        {
            throw new InvalidOperationException("ExeFilename must be specified when RunMode is File");
        }
        
        if (RunMode == AdvancedRunMode.Command && string.IsNullOrEmpty(CommandLine))
        {
            throw new InvalidOperationException("CommandLine must be specified when RunMode is Command");
        }

        if (!File.Exists(AdvancedRunPath))
        {
            throw new FileNotFoundException($"AdvancedRun.exe not found at: {AdvancedRunPath}");
        }

        var arguments = BuildArguments();
        
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = AdvancedRunPath,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            process.Start();
            return process;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to execute AdvancedRun: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Executes the application and waits for it to complete
    /// </summary>
    /// <returns>The exit code of the process</returns>
    public int ExecuteAndWait()
    {
        using var process = Execute();
        if (process == null)
            return -1;

        process.WaitForExit();
        return process.ExitCode;
    }

    /// <summary>
    /// Builds the command line arguments for AdvancedRun.exe
    /// </summary>
    /// <returns>The formatted command line arguments</returns>
    public string BuildArguments()
    {
        var sb = new StringBuilder();

        // Required parameters based on RunMode
        if (RunMode == AdvancedRunMode.File && !string.IsNullOrEmpty(ExeFilename))
        {
            sb.Append($"/EXEFilename \"{ExeFilename}\" ");
        }

        if (!string.IsNullOrEmpty(CommandLine))
            sb.Append($"/CommandLine \"{CommandLine}\" ");

        if (!string.IsNullOrEmpty(StartDirectory))
            sb.Append($"/StartDirectory \"{StartDirectory}\" ");

        // Optional parameters with defaults
        sb.Append($"/WaitProcess {(WaitProcess ? 1 : 0)} ");
        sb.Append($"/PriorityClass {(int)PriorityClass} ");
        sb.Append($"/WindowState {(int)WindowState} ");
        sb.Append($"/RunAs {(int)RunAs} ");

        if (!string.IsNullOrEmpty(RunAsProcessName))
            sb.Append($"/RunAsProcessName \"{RunAsProcessName}\" ");

        sb.Append($"/EnvironmentVariablesMode {(int)EnvironmentVariablesMode} ");
        sb.Append($"/OSCompatMode {(OSCompatMode ? 1 : 0)} ");
        sb.Append($"/UseSearchPath {(UseSearchPath ? 1 : 0)} ");
        sb.Append($"/ParseVarCommandLine {(ParseVarCommandLine ? 1 : 0)} ");
        sb.Append($"/RunMode {(int)RunMode} ");
        sb.Append($"/CommandWindowMode {(int)CommandWindowMode} ");
        sb.Append("/Run");

        return sb.ToString().Trim();
    }

    /// <summary>
    /// Creates a default configuration for running explorer.exe with cmd
    /// </summary>
    /// <returns>A configured AdvancedRun instance</returns>
    public static AdvancedRun CreateExplorerWithCmd()
    {
        return new AdvancedRun
        {
            ExeFilename = @"C:\Windows\explorer.exe",
            CommandLine = "cmd",
            StartDirectory = "",
            WaitProcess = false,
            PriorityClass = ProcessPriorityClass.Normal,
            WindowState = AdvancedRunWindowState.Normal,
            RunAs = AdvancedRunAsMode.CurrentUserAsAdmin,
            RunAsProcessName = "runtimebroker.exe",
            EnvironmentVariablesMode = AdvancedRunEnvironmentVariablesMode.UseCurrent,
            OSCompatMode = false,
            UseSearchPath = false,
            ParseVarCommandLine = false,
            RunMode = AdvancedRunMode.File,
            CommandWindowMode = AdvancedRunCommandWindowMode.Hidden
        };
    }

    #endregion

    #region Overrides

    /// <summary>
    /// Returns a string representation of the AdvancedRun configuration
    /// </summary>
    /// <returns>The command line that would be executed</returns>
    public override string ToString()
    {
        return $"{AdvancedRunPath} {BuildArguments()}";
    }

    #endregion
}
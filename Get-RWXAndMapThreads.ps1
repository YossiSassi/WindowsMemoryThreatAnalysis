<#
.SYNOPSIS
  Scan a process for suspicious executable memory (exec+write and exec-only) and map detected memory regions to threads whose Start Address address lies inside them.
  can be later leveraged for memory threat analysis of threat injection, NOP sleds, syscall stubs, trampoline regions, RWX regions, high-entropy payloads, suspicious strings and more.
  The output json file can later be loaded into 'Invoke-MemoryThreatAnalysis.ps1' for a comprehensive memory threat analysis and a detailed HTML report.

.NOTES
  - Run elevated (Administrator).
  - Use matching bitness (64-bit PowerShell for 64-bit target).
  - This script reads memory (safe). It does not write or inject.
 
  Comments to yossis@protonmail.com
  v1.0.1 - changed default bytes read to 4096 instead 256 so not to miss PE/MZ/other relevant patterns.
  v1.0 - initial script
#>

param(
    [Parameter(Mandatory=$true)][int]$ProcessID,
    [string]$StringToLookFor = 'MZ',
    [int]$ReadBytes = 4096,
    [string]$ExportJson = $null,
    [string]$ExportCsv  = $null
)

# Native interop
$signature = @'
using System;
using System.Runtime.InteropServices;

public static class NativeMethods {
    [Flags]
    public enum ProcessAccessFlags : uint {
        PROCESS_QUERY_INFORMATION = 0x0400,
        PROCESS_VM_READ = 0x0010
    }

    [Flags]
    public enum ThreadAccess : uint {
        THREAD_QUERY_INFORMATION = 0x0040
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    // NtQueryInformationThread (info class 9 = ThreadQuerySetWin32StartAddress)
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, out UIntPtr ThreadInformation, uint ThreadInformationLength, out uint ReturnLength);
}
'@

Add-Type -TypeDefinition $signature -ErrorAction Stop

# Constants / masks
$MEM_COMMIT   = 0x1000
$MEM_PRIVATE  = 0x20000

$PAGE_EXECUTE_READWRITE = 0x40
$PAGE_EXECUTE_WRITECOPY = 0x80
$PAGE_EXECUTE_READ      = 0x20

# Which protections we want to flag (adjust as needed)
$ExecWriteMasks = @($PAGE_EXECUTE_READWRITE, $PAGE_EXECUTE_WRITECOPY)
$ExecOnlyMasks  = @($PAGE_EXECUTE_READ)

# Helper: hex + ascii sample
function Format-HexAscii {
    param([byte[]]$data, [int]$bytesPerLine = 16)
    $sb = New-Object System.Text.StringBuilder
    for ($i=0; $i -lt $data.Length; $i += $bytesPerLine) {
        $end = [Math]::Min($i + $bytesPerLine - 1, $data.Length - 1)
        $line = $data[$i..$end]
        $hex = ($line | ForEach-Object { $_.ToString("X2") }) -join ' '
        $ascii = ($line | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } }) -join ''
        $sb.AppendLine(("{0,8:x}: {1,-48}  {2}" -f $i, $hex, $ascii)) | Out-Null
    }
    return $sb.ToString()
}

# sanity check - get process
try {
    $proc = Get-Process -Id $ProcessID -ErrorAction Stop
} catch {
    Write-Error "Process with PID $ProcessID not found or access denied."
    return
}

# convert string to look for (default = MZ) to Hex bytes
$StringToLookFor | Format-Hex | select -ExpandProperty bytes | foreach { $HexToLookFor += "$([convert]::ToString($_,16)) "}

# warn about bitness mismatch
$psBit = if ([Environment]::Is64BitProcess) { '64-bit' } else { '32-bit' }
Write-Host "`nPowerShell host: $psBit. Target process: $($proc.ProcessName) (PID $ProcessID)" -ForegroundColor Cyan
Write-Host "Ensure you run matching bitness for 64-bit targets." -ForegroundColor DarkYellow

# open target process
$access = [uint32]([NativeMethods+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION) -bor [uint32]([NativeMethods+ProcessAccessFlags]::PROCESS_VM_READ)
$hProc = [NativeMethods]::OpenProcess($access, $false, [uint32]$ProcessID)
if ($hProc -eq [IntPtr]::Zero) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Error "OpenProcess failed (error $err). Try running elevated / enabling SeDebugPrivilege."
    return
}

# prepare struct size
$mbiInstance = New-Object NativeMethods+MEMORY_BASIC_INFORMATION
$mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf($mbiInstance)
$mbiSizePtr = [UIntPtr]::op_Explicit([uint64]$mbiSize)

# iterate address space
$addr = [UIntPtr]::Zero
$maxAddr = if ([Environment]::Is64BitOperatingSystem) { [uint64]0x7FFFFFFFFFFFFFFF } else { [uint64]0x7FFFFFFF }
$results = @()

try {
    while ($true) {
        $mbi = New-Object NativeMethods+MEMORY_BASIC_INFORMATION
        $ret = [NativeMethods]::VirtualQueryEx($hProc, $addr, [ref]$mbi, $mbiSizePtr)
        if ($ret -eq [UIntPtr]::Zero) { break }

        $base = $mbi.BaseAddress.ToUInt64()
        $regionSize = $mbi.RegionSize.ToUInt64()
        $state = $mbi.State
        $type  = $mbi.Type
        $protect = $mbi.Protect

        # only consider committed private regions
        if ((($state -band $MEM_COMMIT) -ne 0) -and ((($type -band $MEM_PRIVATE) -ne 0))) {

            $isExecWrite = $false
            foreach ($m in $ExecWriteMasks) { if (($protect -band $m) -ne 0) { $isExecWrite = $true; break } }

            $isExecOnly = $false
            foreach ($m in $ExecOnlyMasks) { if (($protect -band $m) -ne 0) { $isExecOnly = $true; break } }

            if ($isExecWrite -or $isExecOnly) {
                $toRead = [int][Math]::Min($ReadBytes, [int64]$regionSize)
                $buf = New-Object byte[] $toRead
                $bytesRead = [UIntPtr]::Zero

                $readOk = [NativeMethods]::ReadProcessMemory($hProc, [UIntPtr]::op_Explicit([uint64]$base), $buf, [UIntPtr]::op_Explicit([uint64]$toRead), [ref]$bytesRead)
                $actualRead = 0
                if ($readOk) { $actualRead = $bytesRead.ToUInt64() }

                $typeLabel = if ($isExecWrite) { "EXEC+WRITE" } elseif ($isExecOnly) { "EXEC-ONLY" } else { "EXEC-?" }

                $entry = [PSCustomObject]@{
                    ImageName   = $proc.Name
                    ProcessID   = $proc.Id
                    BaseAddress = ("0x{0:X16}" -f $base)
                    EndAddress  = ("0x{0:X16}" -f ($base + $regionSize))
                    RegionSize  = $regionSize
                    Protect     = ("0x{0:X}" -f $protect)
                    TypeLabel   = $typeLabel
                    ReadBytes   = $actualRead
                    HexSample   = if ($actualRead -gt 0) { Format-HexAscii -data ($buf[0..([int]$actualRead-1)]) -bytesPerLine 16 } else { "" }
                    Threads     = @()
                }

                $results += $entry

                Write-Host "=== Suspicious region: $($entry.TypeLabel) ===" -ForegroundColor Red
                Write-Host ("Base: {0}  End: {1}  Size: {2} bytes  Protect: {3}" -f $entry.BaseAddress, $entry.EndAddress, $entry.RegionSize, $entry.Protect)
                if ($entry.ReadBytes -gt 0) {
                    # Check for MZ (PE/Executable) in memory - highly suspicious, or any other ascii chars
                    if ($entry.HexSample -like "*$HexToLookFor*") {
                            Write-Host "[!] Suspicious region with '$StringToLookFor' detected [!]" -ForegroundColor Red;
                            # pop-up message
                            #Add-Type -AssemblyName Microsoft.VisualBasic;
                            #[Microsoft.VisualBasic.Interaction]::MsgBox("Process $($proc.ProcessName.ToUpper()) (PID $ProcessID) contains Private-Commit-RWX (PAGE_EXECUTE_READWRITE) region in memory, with MZ ascii", 'Exclamation,MsgBoxSetForeground,Critical', 'Suspicious MZ chars detected') | Out-Null
                            
                            # finally went with balloon tip notification, since msgbox waits for user to click it before continuing, and toast notification take too much code/xml :)
                            Add-Type -AssemblyName System.Windows.Forms;
                            $global:balloonMsg = New-Object System.Windows.Forms.NotifyIcon;
                            $path = (Get-Process -id $pid).Path;
                            $balloonMsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path);
                            $balloonMsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning;
                            $balloonMsg.BalloonTipText = "Process $($proc.ProcessName.ToUpper()) (PID $ProcessID) contains Private-Commit $($entry.TypeLabel) region in memory, with $StringToLookFor in ascii";
                            $balloonMsg.BalloonTipTitle = "Suspicious region with $StringToLookFor chars detected";
                            $balloonMsg.Visible = $true;
                            $balloonMsg.ShowBalloonTip(30000)
                        }
                    Write-Host "Hex/ASCII sample:" -ForegroundColor Green
                    Write-Host $entry.HexSample
                } else {
                    Write-Warning "Could not read memory at region base."
                }
            }
        }

        # advance
        $next = $base + $regionSize
        if ($next -ge $maxAddr) { break }
        $addr = [UIntPtr]::op_Explicit([uint64]$next)
    }

    # map threads by their START address (non-intrusive)
    if ($results.Count -gt 0) {
        Write-Host "`nMapping thread START addresses into flagged regions..." -ForegroundColor Cyan

        # build numeric region list for containment checks
        $regionList = $results | ForEach-Object {
            [PSCustomObject]@{
                Base = [UInt64]::Parse(($_.BaseAddress).Substring(2), [System.Globalization.NumberStyles]::HexNumber)
                End  = [UInt64]::Parse(($_.EndAddress).Substring(2), [System.Globalization.NumberStyles]::HexNumber)
                Obj  = $_
            }
        }

        foreach ($t in $proc.Threads) {
            $tid = [uint32]$t.Id
            # open thread for query info
            $hThread = [NativeMethods]::OpenThread([uint32][NativeMethods+ThreadAccess]::THREAD_QUERY_INFORMATION, $false, $tid)
            if ($hThread -eq [IntPtr]::Zero) { continue }

            try {
                $startAddr = [UIntPtr]::Zero
                $retLen = 0
                $ntres = [NativeMethods]::NtQueryInformationThread($hThread, 9, [ref]$startAddr, [uint32][UIntPtr]::Size, [ref]$retLen)
                if ($ntres -eq 0) {
                    $addr64 = $startAddr.ToUInt64()
                    foreach ($r in $regionList) {
                        if ($addr64 -ge $r.Base -and $addr64 -lt $r.End) {
                            # record thread info
                            $r.Obj.Threads += [PSCustomObject]@{
                                ThreadId = $tid
                                StartAddress = ("0x{0:X16}" -f $addr64)
                            }
                            Write-Host ("Thread {0} START {1} inside region {2}" -f $tid, ("0x{0:X16}" -f $addr64), ("0x{0:X16}" -f $r.Base)) -ForegroundColor Yellow
                        }
                    }
                }
            } finally {
                [NativeMethods]::CloseHandle($hThread) | Out-Null
            }
        }
    }

} finally {
    [NativeMethods]::CloseHandle($hProc) | Out-Null
}

# Exports
if ($ExportJson) {
    $results | ConvertTo-Json -Depth 6 | Out-File -FilePath $ExportJson -Encoding UTF8 -Append
    Write-Host "Exported JSON to $ExportJson" -ForegroundColor Cyan
}
if ($ExportCsv) {
    $flat = foreach ($r in $results) {
        $threadList = if ($r.Threads.Count -gt 0) { ($r.Threads | ForEach-Object { $_.ThreadId }) -join ";" } else { "" }
        [PSCustomObject]@{
            BaseAddress = $r.BaseAddress
            EndAddress  = $r.EndAddress
            RegionSize  = $r.RegionSize
            Protect     = $r.Protect
            TypeLabel   = $r.TypeLabel
            ReadBytes   = $r.ReadBytes
            Threads     = $threadList
        }
    }
    $flat | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported CSV to $ExportCsv" -ForegroundColor Cyan
}

if ($results.Count -eq 0) {
    Write-Host "No suspicious exec+write or exec-only private committed regions found." -ForegroundColor Green
} else {
    Write-Host "Scan complete. Found $($results.Count) suspicious region(s)." -ForegroundColor Yellow
}
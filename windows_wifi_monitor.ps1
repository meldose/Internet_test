param(
    [string]$AdapterName,
    [double]$IntervalSeconds = 1.0,
    [string]$OutputDir = $PSScriptRoot,
    [string]$Prefix = "windows_wifi_monitor",
    [int]$EventContextSeconds = 120,
    [int]$EventContextCount = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-IsoTimestamp {
    return (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
}

function Get-LogTimestamp {
    return (Get-Date).ToString("yyyy-MM-dd HH:mm:ss,fff")
}

function Write-LogLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = "{0} {1} {2}" -f (Get-LogTimestamp), $Level.ToUpperInvariant(), $Message
    $script:LogWriter.WriteLine($line)
    $script:LogWriter.Flush()
    Write-Host $line
}

function Write-JsonEvent {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Payload
    )

    $script:JsonWriter.WriteLine(($Payload | ConvertTo-Json -Depth 8 -Compress))
    $script:JsonWriter.Flush()
}

function Parse-NetshInterfaces {
    $lines = netsh wlan show interfaces 2>&1
    $entries = New-Object System.Collections.Generic.List[hashtable]
    $current = $null

    foreach ($line in $lines) {
        if ($line -match '^\s*Name\s*:\s*(.+?)\s*$') {
            if ($null -ne $current) {
                $entries.Add($current)
            }
            $current = [ordered]@{
                Name = $Matches[1].Trim()
                RawLines = New-Object System.Collections.Generic.List[string]
            }
            $current.RawLines.Add($line)
            continue
        }

        if ($null -eq $current) {
            continue
        }

        $current.RawLines.Add($line)
        if ($line -match '^\s*([^:]+?)\s*:\s*(.*?)\s*$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            $current[$key] = $value
        }
    }

    if ($null -ne $current) {
        $entries.Add($current)
    }

    return @($entries.ToArray())
}

function Get-WifiAdapterName {
    param([string]$RequestedName)

    if ($RequestedName) {
        return $RequestedName
    }

    $reports = Parse-NetshInterfaces
    if ($reports.Count -gt 0) {
        return [string]$reports[0]["Name"]
    }

    $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match 'wi-?fi|wlan|wireless' -or
            $_.InterfaceDescription -match 'wi-?fi|wlan|wireless|802\.11'
        } |
        Sort-Object Name |
        Select-Object -First 1

    if ($null -ne $adapter) {
        return [string]$adapter.Name
    }

    throw "No Windows Wi-Fi adapter detected. Pass one explicitly with -AdapterName."
}

function Get-RecentWlanEvents {
    param(
        [int]$ContextSeconds,
        [int]$ContextCount
    )

    try {
        return Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-WLAN-AutoConfig/Operational"
            StartTime = (Get-Date).AddSeconds(-1 * [Math]::Abs($ContextSeconds))
        } -ErrorAction Stop |
            Sort-Object TimeCreated -Descending |
            Select-Object -First $ContextCount |
            Sort-Object TimeCreated
    } catch {
        return @()
    }
}

function Format-WlanEventLines {
    param([object[]]$Events)

    $formatted = New-Object System.Collections.Generic.List[string]
    foreach ($event in $Events) {
        $message = (($event.Message -split '\r?\n') -join ' ') -replace '\s+', ' '
        $formatted.Add(("[{0}] [{1}] {2}" -f $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff"), $event.Id, $message.Trim()))
    }
    return @($formatted.ToArray())
}

function Infer-WifiReason {
    param(
        [string[]]$EventLines,
        [pscustomobject]$Snapshot
    )

    $joined = ($EventLines -join " ").ToLowerInvariant()
    $patterns = @(
        @{ Code = "authentication-failed"; Summary = "Authentication or credential failure"; Regex = "auth|credential|802\.1x|pre-shared|key material|security key" },
        @{ Code = "ap-lost"; Summary = "Access point became unavailable or moved out of range"; Regex = "ssid|network not available|not available|not in range|beacon|access point" },
        @{ Code = "roaming"; Summary = "Roaming or signal-quality transition"; Regex = "roam|signal|quality|better ap" },
        @{ Code = "driver-or-adapter"; Summary = "Wireless adapter or driver reported an error"; Regex = "driver|adapter|hardware|reset|miniport" },
        @{ Code = "radio-disabled"; Summary = "Wireless radio was disabled"; Regex = "radio|turned off|disabled|airplane" },
        @{ Code = "manual-disconnect"; Summary = "Connection was manually disconnected"; Regex = "user initiated|manually|disconnect request" }
    )

    foreach ($pattern in $patterns) {
        if ($joined -match $pattern.Regex) {
            return $pattern
        }
    }

    if (-not $Snapshot.Connected) {
        return @{ Code = "disconnected"; Summary = "Windows Wi-Fi interface is disconnected"; Regex = "" }
    }

    return @{ Code = "unknown"; Summary = "No specific Windows Wi-Fi reason matched"; Regex = "" }
}

function Get-MapValue {
    param(
        [System.Collections.IDictionary]$Map,
        [string]$Key
    )

    if ($null -eq $Map) {
        return ""
    }
    if ($Map.Contains($Key)) {
        return [string]$Map[$Key]
    }
    return ""
}

function Get-WifiSnapshot {
    param([string]$Name)

    $reports = Parse-NetshInterfaces
    $report = $reports | Where-Object { $_["Name"] -eq $Name } | Select-Object -First 1
    $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
    $ipConfig = Get-NetIPConfiguration -InterfaceAlias $Name -ErrorAction SilentlyContinue

    $state = ""
    $ssid = ""
    $bssid = ""
    $signal = ""
    $radio = ""
    $channel = ""
    $receiveRateMbps = ""
    $transmitRateMbps = ""

    if ($null -ne $report) {
        $state = Get-MapValue -Map $report -Key "State"
        $ssid = Get-MapValue -Map $report -Key "SSID"
        $bssid = Get-MapValue -Map $report -Key "BSSID"
        $signal = Get-MapValue -Map $report -Key "Signal"
        $radio = Get-MapValue -Map $report -Key "Radio type"
        $channel = Get-MapValue -Map $report -Key "Channel"
        $receiveRateMbps = Get-MapValue -Map $report -Key "Receive rate (Mbps)"
        $transmitRateMbps = Get-MapValue -Map $report -Key "Transmit rate (Mbps)"
    }

    $connected = $false
    if ($state) {
        $connected = ($state -match '^connected$')
    } elseif ($null -ne $adapter) {
        $connected = ($adapter.Status -eq "Up")
    }

    $ipv4Address = ""
    $defaultGateway = ""
    if ($null -ne $ipConfig) {
        if ($null -ne $ipConfig.IPv4Address) {
            $firstAddress = $ipConfig.IPv4Address | Select-Object -First 1
            if ($null -ne $firstAddress) {
                $ipv4Address = [string]$firstAddress.IPAddress
            }
        }
        if ($null -ne $ipConfig.IPv4DefaultGateway) {
            $firstGateway = $ipConfig.IPv4DefaultGateway | Select-Object -First 1
            if ($null -ne $firstGateway) {
                $defaultGateway = [string]$firstGateway.NextHop
            }
        }
    }

    $adapterStatus = ""
    $macAddress = ""
    $linkSpeed = ""
    $interfaceDescription = ""
    if ($null -ne $adapter) {
        $adapterStatus = [string]$adapter.Status
        $macAddress = [string]$adapter.MacAddress
        $linkSpeed = [string]$adapter.LinkSpeed
        $interfaceDescription = [string]$adapter.InterfaceDescription
    }

    return [pscustomobject]@{
        Timestamp = Get-IsoTimestamp
        AdapterName = $Name
        AdapterStatus = $adapterStatus
        Connected = $connected
        State = $state
        SSID = $ssid
        BSSID = $bssid
        Signal = $signal
        RadioType = $radio
        Channel = $channel
        ReceiveRateMbps = $receiveRateMbps
        TransmitRateMbps = $transmitRateMbps
        IPv4Address = $ipv4Address
        DefaultGateway = $defaultGateway
        MacAddress = $macAddress
        LinkSpeed = $linkSpeed
        InterfaceDescription = $interfaceDescription
    }
}

function Log-Snapshot {
    param(
        [string]$PrefixText,
        [pscustomobject]$Snapshot
    )

    Write-LogLine "INFO" (
        "{0} adapter={1} connected={2} state={3} ssid={4} bssid={5} signal={6} ipv4={7} gateway={8}" -f
        $PrefixText,
        $Snapshot.AdapterName,
        $Snapshot.Connected,
        ("'{0}'" -f $Snapshot.State),
        ("'{0}'" -f $Snapshot.SSID),
        ("'{0}'" -f $Snapshot.BSSID),
        ("'{0}'" -f $Snapshot.Signal),
        ("'{0}'" -f $Snapshot.IPv4Address),
        ("'{0}'" -f $Snapshot.DefaultGateway)
    )
}

function Log-Disconnect {
    param(
        [pscustomobject]$PreviousSnapshot,
        [pscustomobject]$CurrentSnapshot,
        [int]$ContextSeconds,
        [int]$ContextCount
    )

    $events = Get-RecentWlanEvents -ContextSeconds $ContextSeconds -ContextCount $ContextCount
    $eventLines = Format-WlanEventLines -Events $events
    $reason = Infer-WifiReason -EventLines $eventLines -Snapshot $CurrentSnapshot

    Write-LogLine "WARNING" ("WINDOWS WIFI DISCONNECT detected on adapter={0}" -f $CurrentSnapshot.AdapterName)
    Write-LogLine "WARNING" ("Loss time: current_snapshot={0} previous_connected_snapshot={1}" -f $CurrentSnapshot.Timestamp, $PreviousSnapshot.Timestamp)
    Write-LogLine "WARNING" ("Current state: connected={0} state='{1}' ssid='{2}' signal='{3}' ipv4='{4}' gateway='{5}'" -f $CurrentSnapshot.Connected, $CurrentSnapshot.State, $CurrentSnapshot.SSID, $CurrentSnapshot.Signal, $CurrentSnapshot.IPv4Address, $CurrentSnapshot.DefaultGateway)
    Write-LogLine "WARNING" ("Inferred reason: {0} ({1})" -f $reason.Summary, $reason.Code)
    if ($eventLines.Count -gt 0) {
        Write-LogLine "WARNING" "Recent WLAN events around disconnect:"
        foreach ($line in $eventLines) {
            Write-LogLine "WARNING" ("wlan-event: {0}" -f $line)
        }
    }

    Write-JsonEvent @{
        event = "windows_wifi_disconnect"
        timestamp = $CurrentSnapshot.Timestamp
        adapter = $CurrentSnapshot.AdapterName
        reason_code = $reason.Code
        reason_summary = $reason.Summary
        previous_snapshot = $PreviousSnapshot
        current_snapshot = $CurrentSnapshot
        recent_wlan_events = $eventLines
    }
}

function Log-Reconnect {
    param([pscustomobject]$Snapshot)

    Write-LogLine "INFO" ("WINDOWS WIFI RECONNECTED adapter={0} ssid='{1}' bssid='{2}' signal='{3}' ipv4='{4}' gateway='{5}'" -f $Snapshot.AdapterName, $Snapshot.SSID, $Snapshot.BSSID, $Snapshot.Signal, $Snapshot.IPv4Address, $Snapshot.DefaultGateway)
    Write-JsonEvent @{
        event = "windows_wifi_reconnect"
        timestamp = $Snapshot.Timestamp
        adapter = $Snapshot.AdapterName
        snapshot = $Snapshot
    }
}

$adapter = Get-WifiAdapterName -RequestedName $AdapterName
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$resolvedOutputDir = [System.IO.Path]::GetFullPath($OutputDir)
[System.IO.Directory]::CreateDirectory($resolvedOutputDir) | Out-Null

$logPath = Join-Path $resolvedOutputDir ("{0}_{1}_{2}.log" -f $Prefix, $adapter, $timestamp)
$jsonlPath = Join-Path $resolvedOutputDir ("{0}_{1}_{2}.jsonl" -f $Prefix, $adapter, $timestamp)

$script:LogWriter = New-Object System.IO.StreamWriter($logPath, $false, [System.Text.Encoding]::UTF8)
$script:JsonWriter = New-Object System.IO.StreamWriter($jsonlPath, $false, [System.Text.Encoding]::UTF8)

try {
    Write-LogLine "INFO" ("Starting Windows Wi-Fi monitor on adapter={0}" -f $adapter)
    Write-LogLine "INFO" ("Text log: {0}" -f $logPath)
    Write-LogLine "INFO" ("JSONL log: {0}" -f $jsonlPath)

    $previousSnapshot = $null
    $disconnectCount = 0
    $reconnectCount = 0

    while ($true) {
        $snapshot = Get-WifiSnapshot -Name $adapter
        if ($null -eq $previousSnapshot) {
            Log-Snapshot -PrefixText "Initial snapshot:" -Snapshot $snapshot
            Write-JsonEvent @{
                event = "startup"
                timestamp = $snapshot.Timestamp
                adapter = $adapter
                snapshot = $snapshot
            }
        } else {
            if ($previousSnapshot.Connected -and -not $snapshot.Connected) {
                $disconnectCount += 1
                Log-Disconnect -PreviousSnapshot $previousSnapshot -CurrentSnapshot $snapshot -ContextSeconds $EventContextSeconds -ContextCount $EventContextCount
            } elseif (-not $previousSnapshot.Connected -and $snapshot.Connected) {
                $reconnectCount += 1
                Log-Reconnect -Snapshot $snapshot
            }
        }

        $previousSnapshot = $snapshot
        Start-Sleep -Milliseconds ([int]([Math]::Max(200.0, $IntervalSeconds * 1000.0)))
    }
} finally {
    if ($null -ne $previousSnapshot) {
        Write-JsonEvent @{
            event = "shutdown"
            timestamp = Get-IsoTimestamp
            adapter = $adapter
            disconnect_count = $disconnectCount
            reconnect_count = $reconnectCount
            last_snapshot = $previousSnapshot
        }
    }
    Write-LogLine "INFO" ("Stopped Windows Wi-Fi monitor on {0}. disconnects={1} reconnects={2}" -f $adapter, $disconnectCount, $reconnectCount)
    $script:LogWriter.Dispose()
    $script:JsonWriter.Dispose()
}

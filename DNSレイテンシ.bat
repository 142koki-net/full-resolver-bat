@echo off
chcp 65001 >nul
title Root DNS Servers (A-M) Benchmark
powershell -NoProfile -ExecutionPolicy Bypass -Command "$c = Get-Content -LiteralPath '%~f0' -Encoding UTF8; $i = $c.IndexOf('#PS_START#'); & ([scriptblock]::Create(($c[($i+1)..($c.Length-1)] -join \"`n\")))"
pause
exit /b
#PS_START#
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$script:rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

$rootServers = [ordered]@{
    "a.root-servers.net" = "198.41.0.4";   "b.root-servers.net" = "170.247.170.2"
    "c.root-servers.net" = "192.33.4.12";  "d.root-servers.net" = "199.7.91.13"
    "e.root-servers.net" = "192.203.230.10"; "f.root-servers.net" = "192.5.5.241"
    "g.root-servers.net" = "192.112.36.4"; "h.root-servers.net" = "198.97.190.53"
    "i.root-servers.net" = "192.36.148.17"; "j.root-servers.net" = "192.58.128.30"
    "k.root-servers.net" = "193.0.14.129"; "l.root-servers.net" = "199.7.83.42"
    "m.root-servers.net" = "202.12.27.33"
}

# RFC 1035 準拠のドメイン名検証
function Test-ValidDomain([string]$Domain) {
    if ([string]::IsNullOrWhiteSpace($Domain) -or $Domain.Length -gt 253) { return $false }
    $labels = $Domain.Split('.')
    if ($labels.Count -lt 2) { return $false }
    foreach ($label in $labels) {
        if ($label.Length -lt 1 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$') { return $false }
    }
    return $true
}

# 委任先NS用のグローバルIPv4検証（SSRF防止）
function Test-PublicIPv4([string]$IpString) {
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($IpString, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $ip.GetAddressBytes()
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 172 -and ($b[1] -ge 16 -and $b[1] -le 31)) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    return $true
}

# 境界・長さチェック付きDNSドメイン名デコーダ
function Read-DnsName([byte[]]$Buf, [ref]$Offset) {
    $labels = New-Object System.Collections.Generic.List[string]
    $pos = $Offset.Value
    $jumped = $false
    $jumps = 0
    $totalLen = 0

    while ($true) {
        if ($pos -ge $Buf.Length) { throw "Malformed packet: name out of bounds" }
        $len = [int]$Buf[$pos]
        if ($len -eq 0) {
            if (-not $jumped) { $Offset.Value = $pos + 1 }
            break
        }
        $pointerMask = $len -band 0xC0
        if ($pointerMask -eq 0xC0) {
            if (($pos + 1) -ge $Buf.Length) { throw "Malformed packet: truncated pointer" }
            if (++$jumps -gt 16) { throw "Malformed packet: pointer loop detected" }
            if (-not $jumped) { $Offset.Value = $pos + 2; $jumped = $true }
            $pos = (($len -band 0x3F) -shl 8) -bor [int]$Buf[$pos + 1]
            continue
        }
        if ($pointerMask -ne 0) { throw "Malformed packet: invalid label length" }
        $pos++
        if (($pos + $len) -gt $Buf.Length) { throw "Malformed packet: label exceeds buffer" }
        $totalLen += $len + 1
        if ($totalLen -gt 255) { throw "Malformed packet: domain name too long" }
        $labels.Add([System.Text.Encoding]::ASCII.GetString($Buf, $pos, $len))
        $pos += $len
        if (-not $jumped) { $Offset.Value = $pos }
    }
    return ($labels -join '.')
}

# TCビット発生時のTCPフォールバック通信 (RFC 7766)
function Invoke-DnsTcpFallback([string]$ServerIp, [byte[]]$Packet, [int]$TimeoutMs) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.SendTimeout    = $TimeoutMs
        $tcp.ReceiveTimeout = $TimeoutMs
        $ar = $tcp.BeginConnect($ServerIp, 53, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            throw (New-Object System.Net.Sockets.SocketException(10060))
        }
        $tcp.EndConnect($ar)

        $stream = $tcp.GetStream()
        # TCP DNSは先頭に2バイトのメッセージ長プレフィックスを付与する
        $lenPrefix = [byte[]]@([byte]($Packet.Length -shr 8), [byte]($Packet.Length -band 0xFF))
        $stream.Write($lenPrefix, 0, 2)
        $stream.Write($Packet, 0, $Packet.Length)

        $lenBuf = New-Object byte[] 2
        $read = 0
        while ($read -lt 2) {
            $r = $stream.Read($lenBuf, $read, 2 - $read)
            if ($r -le 0) { throw "TCP EOF reading length" }
            $read += $r
        }
        $respLen = ([int]$lenBuf[0] -shl 8) -bor [int]$lenBuf[1]
        if ($respLen -lt 12 -or $respLen -gt 65535) { throw "Invalid TCP response length" }

        $respBuf = New-Object byte[] $respLen
        $read = 0
        while ($read -lt $respLen) {
            $r = $stream.Read($respBuf, $read, $respLen - $read)
            if ($r -le 0) { throw "TCP EOF reading body" }
            $read += $r
        }
        return ,$respBuf
    } finally {
        $tcp.Close()
    }
}

# EDNS0対応・TCPフォールバック付きDNSクエリ実行
function Invoke-DnsQuery([string]$ServerIp, [string]$Domain, [int]$TimeoutMs = 2500) {
    $txBytes = New-Object byte[] 2
    $script:rng.GetBytes($txBytes)

    $qBytes = New-Object System.Collections.Generic.List[byte]
    $qBytes.AddRange($txBytes)
    # Header: Flags=0x0000(RD=0), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1(EDNS0)
    $qBytes.AddRange([byte[]]@(0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01))
    foreach ($label in $Domain.Split('.')) {
        $b = [System.Text.Encoding]::ASCII.GetBytes($label)
        $qBytes.Add([byte]$b.Length)
        $qBytes.AddRange($b)
    }
    # QNAME終端(0x00) + QTYPE=A(1) + QCLASS=IN(1)
    $qBytes.AddRange([byte[]]@(0x00, 0x00, 0x01, 0x00, 0x01))
    # EDNS0 OPT Record: Root(0x00), Type=OPT(41), UDP Payload=1232(0x04D0), RCODE/Flags=0, RDLEN=0
    $qBytes.AddRange([byte[]]@(0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
    $packet = $qBytes.ToArray()

    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.SendTimeout    = $TimeoutMs
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($ServerIp, 53)

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        [void]$udp.Send($packet, $packet.Length)
        $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $buf = $udp.Receive([ref]$remoteEp)
        $sw.Stop()
    } finally {
        $udp.Close()
    }

    if ($buf.Length -lt 12) { throw "Response too short" }
    if ($buf[0] -ne $txBytes[0] -or $buf[1] -ne $txBytes[1]) { throw "TXID mismatch" }
    if (($buf[2] -band 0x80) -eq 0) { throw "Not a response packet" }

    # TCビット(0x02)が立っている場合はTCPで再取得して時間を加算
    if (($buf[2] -band 0x02) -ne 0) {
        $sw.Start()
        $buf = Invoke-DnsTcpFallback -ServerIp $ServerIp -Packet $packet -TimeoutMs $TimeoutMs
        $sw.Stop()
        if ($buf[0] -ne $txBytes[0] -or $buf[1] -ne $txBytes[1]) { throw "TCP TXID mismatch" }
        if (($buf[2] -band 0x80) -eq 0) { throw "Invalid TCP response" }
    }

    $rcode   = $buf[3] -band 0x0F
    $qdCount = ([int]$buf[4] -shl 8) -bor [int]$buf[5]
    $anCount = ([int]$buf[6] -shl 8) -bor [int]$buf[7]
    $nsCount = ([int]$buf[8] -shl 8) -bor [int]$buf[9]
    $arCount = ([int]$buf[10] -shl 8) -bor [int]$buf[11]

    if ($qdCount -ne 1) { throw "Unexpected QDCOUNT: $qdCount" }
    $offset = 12
    $qName = Read-DnsName -Buf $buf -Offset ([ref]$offset)
    if ($qName -ine $Domain) { throw "QNAME mismatch: $qName" }
    if (($offset + 4) -gt $buf.Length) { throw "Malformed question section" }
    $offset += 4

    $ansA     = $null
    $ansCname = $null
    $nsList   = New-Object System.Collections.Generic.List[string]
    $glueMap  = @{}

    $totalRr = $anCount + $nsCount + $arCount
    for ($i = 0; $i -lt $totalRr; $i++) {
        $rrName = Read-DnsName -Buf $buf -Offset ([ref]$offset)
        if (($offset + 10) -gt $buf.Length) { throw "Malformed RR header" }
        $rrType = ([int]$buf[$offset] -shl 8) -bor [int]$buf[$offset + 1]
        $rdLen  = ([int]$buf[$offset + 8] -shl 8) -bor [int]$buf[$offset + 9]
        $offset += 10
        if (($offset + $rdLen) -gt $buf.Length) { throw "Malformed RDATA length" }

        $rdataPos = $offset
        if ($i -lt $anCount) {
            if ($rrType -eq 1 -and $rdLen -eq 4 -and -not $ansA) {
                $ansA = "$($buf[$offset]).$($buf[$offset+1]).$($buf[$offset+2]).$($buf[$offset+3])"
            } elseif ($rrType -eq 5) {
                $ansCname = Read-DnsName -Buf $buf -Offset ([ref]$rdataPos)
            }
        } elseif ($i -lt ($anCount + $nsCount)) {
            if ($rrType -eq 2) {
                $nsList.Add((Read-DnsName -Buf $buf -Offset ([ref]$rdataPos)))
            }
        } else {
            # OPTレコード(Type=41)等は無視し、Glue Aレコード(Type=1)のみ抽出
            if ($rrType -eq 1 -and $rdLen -eq 4 -and -not $glueMap.ContainsKey($rrName)) {
                $glueMap[$rrName] = "$($buf[$offset]).$($buf[$offset+1]).$($buf[$offset+2]).$($buf[$offset+3])"
            }
        }
        $offset += $rdLen
    }

    return [PSCustomObject]@{
        RCode     = $rcode
        ElapsedMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
        AnswerA   = $ansA
        CName     = $ansCname
        NsList    = $nsList
        GlueMap   = $glueMap
    }
}

# ルートサーバー起点の反復解決関数
function Resolve-Iterative([string]$Domain, [hashtable]$State, [int]$Depth = 0) {
    if ($Depth -gt 3) { return @{ Status = "Max NS Depth"; IP = "-" } }

    $target  = $Domain
    $curName = $State.RootHost
    $curIp   = $State.RootIp
    $indent  = "  " * ($Depth + 1)
    $prefix  = if ($Depth -gt 0) { "[NS解決] " } else { "" }

    while ($State.Hops -lt $State.MaxHops) {
        $State.Hops++
        $hopNo = $State.Hops

        $res = Invoke-DnsQuery -ServerIp $curIp -Domain $target
        $State.TotalMs += $res.ElapsedMs
        if ($hopNo -eq 1) { $State.RootMs = $res.ElapsedMs }

        if ($res.RCode -ne 0) {
            $st = if ($res.RCode -eq 3) { "NXDOMAIN" } else { "RCode:$($res.RCode)" }
            Write-Host ("{0}+-- {1}Hop {2} {3,-24} ({4,-15}) : {5,6} ms -> {6}" -f $indent, $prefix, $hopNo, $curName, $curIp, $res.ElapsedMs, $st) -ForegroundColor Red
            return @{ Status = $st; IP = "-" }
        }

        if ($res.AnswerA) {
            Write-Host ("{0}+-- {1}Hop {2} {3,-24} ({4,-15}) : {5,6} ms -> 完了 A: {6}" -f $indent, $prefix, $hopNo, $curName, $curIp, $res.ElapsedMs, $res.AnswerA) -ForegroundColor Green
            return @{ Status = "OK"; IP = $res.AnswerA }
        }

        if ($res.CName) {
            if (-not (Test-ValidDomain -Domain $res.CName)) { throw "Invalid CNAME target" }
            Write-Host ("{0}|-- {1}Hop {2} {3,-24} ({4,-15}) : {5,6} ms -> CNAME: {6}" -f $indent, $prefix, $hopNo, $curName, $curIp, $res.ElapsedMs, $res.CName) -ForegroundColor Magenta
            $target  = $res.CName
            $curName = $State.RootHost
            $curIp   = $State.RootIp
            continue
        }

        if ($res.NsList.Count -gt 0) {
            $nextName = $res.NsList[0]
            $nextIp   = $null
            foreach ($ns in $res.NsList) {
                if ($res.GlueMap.ContainsKey($ns)) {
                    $nextName = $ns
                    $nextIp   = $res.GlueMap[$ns]
                    break
                }
            }

            if ($nextIp) {
                if (-not (Test-PublicIPv4 -IpString $nextIp)) { throw "Invalid/Private Glue IP: $nextIp" }
                Write-Host ("{0}|-- {1}Hop {2} {3,-24} ({4,-15}) : {5,6} ms -> 委任: {6} ({7})" -f $indent, $prefix, $hopNo, $curName, $curIp, $res.ElapsedMs, $nextName, $nextIp) -ForegroundColor Gray
            } else {
                if (-not (Test-ValidDomain -Domain $nextName)) { throw "Invalid NS host" }
                Write-Host ("{0}|-- {1}Hop {2} {3,-24} ({4,-15}) : {5,6} ms -> 委任: {6} (Glueなし -> ルートから解決)" -f $indent, $prefix, $hopNo, $curName, $curIp, $res.ElapsedMs, $nextName) -ForegroundColor DarkYellow
                $sub = Resolve-Iterative -Domain $nextName -State $State -Depth ($Depth + 1)
                if ($sub.Status -ne "OK") {
                    return @{ Status = "NS $($sub.Status)"; IP = "-" }
                }
                if (-not (Test-PublicIPv4 -IpString $sub.IP)) { throw "Invalid/Private NS IP: $($sub.IP)" }
                $nextIp = $sub.IP
            }

            $curName = $nextName
            $curIp   = $nextIp
            continue
        }

        return @{ Status = "No A Record"; IP = "-" }
    }

    return @{ Status = "Max Hops"; IP = "-" }
}

while ($true) {
    Write-Host ""
    $rawInput = Read-Host "計測するドメイン名を入力してください (例: www.google.com / 終了は未入力でEnter)"
    if ([string]::IsNullOrWhiteSpace($rawInput)) { break }

    $domain = ($rawInput.Trim() -replace '^https?://', '' -replace '/.*$', '').TrimEnd('.')
    if (-not (Test-ValidDomain -Domain $domain)) {
        Write-Host "[エラー] 無効なドメイン名形式です。半角英数字とドットで正しく入力してください。" -ForegroundColor Red
        continue
    }

    Write-Host "`n[$domain] のAレコード取得時間を計測中..." -ForegroundColor Cyan

    $results = foreach ($entry in $rootServers.GetEnumerator()) {
        $state = @{
            RootHost = $entry.Key
            RootIp   = $entry.Value
            RootMs   = $null
            TotalMs  = 0.0
            Hops     = 0
            MaxHops  = 20
        }

        Write-Host "`n[$($state.RootHost)]" -ForegroundColor Yellow

        try {
            $res = Resolve-Iterative -Domain $domain -State $state -Depth 0
            $status    = $res.Status
            $resolvedA = $res.IP
        } catch [System.Net.Sockets.SocketException] {
            $status    = "Timeout/Unreachable"
            $resolvedA = "-"
            Write-Host ("  +-- Hop {0} -> {1}" -f $state.Hops, $status) -ForegroundColor Red
        } catch {
            $status    = "Error: $($_.Exception.Message)"
            $resolvedA = "-"
            Write-Host ("  +-- Hop {0} -> {1}" -f $state.Hops, $status) -ForegroundColor Red
        }

        [PSCustomObject]@{
            RootServer  = $state.RootHost
            RootIP      = $state.RootIp
            "Root(ms)"  = if ($null -ne $state.RootMs) { $state.RootMs } else { "-" }
            "Total(ms)" = if ($status -eq "OK") { [math]::Round($state.TotalMs, 2) } else { "-" }
            Hops        = $state.Hops
            ResolvedIP  = $resolvedA
            Status      = $status
        }
    }

    Write-Host "`n=== 計測結果: $domain ===" -ForegroundColor Green
    $results | Format-Table -AutoSize
}
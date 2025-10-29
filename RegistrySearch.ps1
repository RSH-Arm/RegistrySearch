param(
    [Parameter(Mandatory=$true)]
    [string]$AppName,
    
    [string]$OutputFile,
    
    [switch]$ExportReg,
    
    [string]$RegExportFile,
    
    [switch]$IncludeClassesRoot,
    
    [switch]$IncludeUsers,
    
    [switch]$IncludeAllHives,
    
    [int]$MaxDepth = 10,
    
    [switch]$ExactMatch,
    [switch]$IncludeStandardPaths,
    [switch]$FilterFalsePositives,
	
    [ValidateSet("Auto", "SingleThread", "MultiThread")]
    [string]$ThreadingMode = "Auto"
)

# =============================================================================
# КОНФИГУРАЦИОННАЯ СИСТЕМА
# =============================================================================
$Script:Config = @{
    Search = @{
        DefaultMaxDepth = 10
        MaxExecutionTimeMinutes = 30
        AutoThreadingThreshold = 2
        BatchSize = 100
    }
    Safety = @{
        ScoreThresholds = @{
            Safe = -5
            Caution = 2
            Dangerous = 8
            Critical = 9
        }
        SystemPatterns = @(
            "*\Windows\*",
            "*\Microsoft\*", 
            "*\System32\*",
            "*\SysWOW64\*"
        )
    }
    Performance = @{
        MemoryLimitMB = 500
        CacheEnabled = $true
        CleanupInterval = 100
    }
    Logging = @{
        Enabled = $true
        Debug = $false
    }
}

# Интеллектуальные шаблоны для популярных приложений
$Script:IntelligentPatterns = @{
    "Adobe" = @{
        Paths = @(
            "*\Adobe\*",
            "*\Acrobat\*",
            "*\Photoshop\*",
            "*\Illustrator\*"
        )
        SafePatterns = @(
            "*\Settings\*",
            "*\Cache\*", 
            "*\Logs\*",
            "*\Temp\*"
        )
        DangerousPatterns = @(
            "*\Registration\*",
            "*\Licensing\*",
            "*\Activation\*"
        )
    }
    "Microsoft Office" = @{
        Paths = @(
            "*\Microsoft Office\*",
            "*\Office\*",
            "*\Word\*",
            "*\Excel\*",
            "*\PowerPoint\*"
        )
        SafePatterns = @(
            "*\User Settings\*",
            "*\Recent\*",
            "*\Cache\*"
        )
        DangerousPatterns = @(
            "*\Registration\*",
            "*\Licensing\*",
            "*\DigitalLocker\*"
        )
    }
    "Autodesk" = @{
        Paths = @(
            "*\Autodesk\*",
            "*\AutoCAD\*",
            "*\Revit\*",
            "*\3ds Max\*"
        )
        SafePatterns = @(
            "*\Cache\*",
            "*\Logs\*",
            "*\Temp\*",
            "*\Recent\*"
        )
        DangerousPatterns = @(
            "*\Licensing\*",
            "*\Authorization\*",
            "*\Activation\*"
        )
    }
}

# =============================================================================
# ЕДИНАЯ СИСТЕМА КЭШИРОВАНИЯ
# =============================================================================
$Script:RegistryCache = @{
    KeyDetails = @{}
    SearchResults = @{}
    Timestamps = @{}
}

function Get-CachedRegistryKey {
    param([string]$Path)
    
    $cacheKey = $Path.ToLower()
    
    # Проверяем актуальность кэша (5 минут)
    if ($Script:RegistryCache.KeyDetails.ContainsKey($cacheKey)) {
        $cacheTime = $Script:RegistryCache.Timestamps[$cacheKey]
        if ((Get-Date) - $cacheTime -le (New-TimeSpan -Minutes 5)) {
            return $Script:RegistryCache.KeyDetails[$cacheKey]
        }
    }
    
    # Если нет в кэше или устарел - получаем данные
    $keyDetails = Get-RegistryKeyDetails -RegistryPath $Path
    $Script:RegistryCache.KeyDetails[$cacheKey] = $keyDetails
    $Script:RegistryCache.Timestamps[$cacheKey] = Get-Date
    
    return $keyDetails
}

function Clear-RegistryCache {
    param([string]$CacheType = "All")
    
    switch ($CacheType) {
        "KeyDetails" { 
            $Script:RegistryCache.KeyDetails.Clear()
            $Script:RegistryCache.Timestamps.Clear()
        }
        "SearchResults" { $Script:RegistryCache.SearchResults.Clear() }
        "All" { 
            $Script:RegistryCache.KeyDetails.Clear() 
            $Script:RegistryCache.SearchResults.Clear()
            $Script:RegistryCache.Timestamps.Clear()
        }
    }
    
    Write-Host "Кэш очищен: $CacheType" -ForegroundColor Yellow
}

# =============================================================================
# УПРОЩЕННОЕ УПРАВЛЕНИЕ ПАМЯТЬЮ
# =============================================================================
function Invoke-MemoryManagement {
    param([int]$IterationCount = 0)
    
    # Выполняем очистку каждые N итераций
    if ($IterationCount % $Script:Config.Performance.CleanupInterval -eq 0) {
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($process) {
            $memoryMB = $process.WorkingSet / 1MB
            
            if ($memoryMB -gt $Script:Config.Performance.MemoryLimitMB) {
                Write-Host "Предупреждение: Использование памяти: $([math]::Round($memoryMB, 2)) MB" -ForegroundColor Yellow
                Clear-RegistryCache -CacheType "KeyDetails"
                
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
                
                Start-Sleep -Milliseconds 100
            }
        }
    }
}

# =============================================================================
# ЦЕНТРАЛИЗОВАННОЕ ЛОГИРОВАНИЕ
# =============================================================================
class RegistrySearchLogger {
    [string]$LogPath
    [bool]$DebugEnabled
    [string]$OutputDir
    [hashtable]$ColorMap
    
    RegistrySearchLogger([string]$OutputDirectory) {
        $this.OutputDir = $OutputDirectory
        $this.LogPath = Join-Path $OutputDirectory "RegistrySearch_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $this.DebugEnabled = $false
		$this.ColorMap = @{
			"INFO" = "White"
			"WARN" = "Yellow" 
			"ERROR" = "Red"
			"DEBUG" = "Gray"
			"SUCCESS" = "Green"
		}
    }
    
    [void] EnableDebug() {
        $this.DebugEnabled = $true
    }
    
    [void] LogInfo([string]$Message) {
        $this.WriteLog("INFO", $Message)
    }
    
    [void] LogWarning([string]$Message) {
        $this.WriteLog("WARN", $Message)
    }
    
    [void] LogError([string]$Message) {
        $this.WriteLog("ERROR", $Message)
    }
    
    [void] LogDebug([string]$Message) {
        if ($this.DebugEnabled) {
            $this.WriteLog("DEBUG", $Message)
        }
    }
    
    [void] LogSuccess([string]$Message) {
        $this.WriteLog("SUCCESS", $Message)
    }
    
	hidden [void] WriteLog([string]$Level, [string]$Message) {
		$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
		$logEntry = "[$timestamp] [$Level] $Message"
		
		# Вывод в консоль с безопасной обработкой цвета
		try {
			$colorName = $this.ColorMap[$Level]
			
			if (-not [string]::IsNullOrWhiteSpace($colorName)) {
				$consoleColor = $null
				if ([System.Enum]::TryParse([System.ConsoleColor], $colorName, [ref]$consoleColor)) {
					Write-Host $logEntry -ForegroundColor $consoleColor
				}
				else {
					Write-Host $logEntry
				}
			}
			else {
				Write-Host $logEntry
			}
		}
		catch {
			Write-Host $logEntry
		}
		
		# Запись в файл
		try {
			$logEntry | Out-File -FilePath $this.LogPath -Append -Encoding UTF8
		}
		catch {
			# Не блокируем выполнение при ошибках записи лога
		}
	}
    
    [string] GetLogPath() {
        return $this.LogPath
    }
}

# =============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ ПАТТЕРНОВ
# =============================================================================
function Test-PathPattern {
    param([string]$Path, [array]$Patterns)
    
    foreach ($pattern in $Patterns) {
        if ($Path -like $pattern) {
            return $true
        }
    }
    return $false
}

function Get-IntelligentSearchPatterns {
    param([string]$AppName)
    
    foreach ($appPattern in $Script:IntelligentPatterns.Keys) {
        if ($AppName -like "*$appPattern*" -or $appPattern -like "*$AppName*") {
            Write-Host "Обнаружено интеллектуальное правило для: $appPattern" -ForegroundColor Cyan
            return $Script:IntelligentPatterns[$appPattern]
        }
    }
    
    return $null
}

function Apply-IntelligentSearch {
    param([string]$AppName, [ref]$SearchPattern, [ref]$MaxDepth)
    
    $intelligentRules = Get-IntelligentSearchPatterns -AppName $AppName
    if ($intelligentRules) {
        Write-Host "Применяются интеллектуальные правила поиска..." -ForegroundColor Cyan
        
        if ($intelligentRules.Paths.Count -gt 10) {
            $MaxDepth.Value = [math]::Min($MaxDepth.Value, 8)
        }
    }
}

# =============================================================================
# УНИФИЦИРОВАННАЯ ФУНКЦИЯ АНАЛИЗА КЛЮЧЕЙ РЕЕСТРА
# =============================================================================
function Get-RegistryKeyDetails {
    param([string]$RegistryPath)
    
    $details = @{
        LastWriteTime = "Не доступно"
        SubKeyCount = 0
        ValueCount = 0
        IsSystemKey = $false
        ContainsUserData = $false
        ContainsSettings = $false
        ContainsFileAssociations = $false
        ImportanceScore = 0
    }
    
    try {
        if (Test-Path $RegistryPath -ErrorAction SilentlyContinue) {
            $key = Get-Item $RegistryPath -ErrorAction SilentlyContinue
            $details.LastWriteTime = if ($key.LastWriteTime) { $key.LastWriteTime.ToString() } else { "Не доступно" }
            $details.ValueCount = $key.ValueCount
            
            try {
                $subKeys = Get-ChildItem $RegistryPath -ErrorAction SilentlyContinue
                $details.SubKeyCount = $subKeys.Count
            } catch {
                $details.SubKeyCount = 0
            }
            
            # Комплексный анализ содержимого ключа
            $userDataPatterns = @("*\Recent*", "*\History*", "*\Cache*", "*\Temp*", "*\Log*", "*\Data*", "*\Storage*", "*\Profiles*", "*\Users*")
            $settingsPatterns = @("*\Settings*", "*\Options*", "*\Preferences*", "*\Configuration*", "*\Parameters*")
            $fileAssocPatterns = @("*\.$AppName*", "*\$AppName\shell*", "*\$AppName\DefaultIcon*", "*\Classes\*$AppName*")
            $systemPatterns = @("*\Microsoft\*", "*\Windows\*", "*\System*", "*\CurrentControlSet*", "*\Policies*", "*\Classes\*")
            
            $details.ContainsUserData = Test-PathPattern -Path $RegistryPath -Patterns $userDataPatterns
            $details.ContainsSettings = Test-PathPattern -Path $RegistryPath -Patterns $settingsPatterns
            $details.ContainsFileAssociations = Test-PathPattern -Path $RegistryPath -Patterns $fileAssocPatterns
            $details.IsSystemKey = Test-PathPattern -Path $RegistryPath -Patterns $systemPatterns
            
            # Расчет важности ключа
            if ($details.ContainsUserData) { $details.ImportanceScore += 2 }
            if ($details.ContainsSettings) { $details.ImportanceScore += 3 }
            if ($details.ContainsFileAssociations) { $details.ImportanceScore += 4 }
            if ($details.IsSystemKey) { $details.ImportanceScore += 5 }
            if ($details.SubKeyCount -gt 10) { $details.ImportanceScore += 2 }
            if ($details.ValueCount -gt 5) { $details.ImportanceScore += 1 }
            
            # Дополнительные проверки по пути
            if ($RegistryPath -like "*\Run*") { $details.ImportanceScore += 4 }
            if ($RegistryPath -like "*\Services*") { $details.ImportanceScore += 5 }
            if ($RegistryPath -like "*\Drivers*") { $details.ImportanceScore += 5 }
            if ($RegistryPath -like "*\AppPaths*") { $details.ImportanceScore += 3 }
        }
    }
    catch {
        # Не блокируем выполнение при ошибках
    }
    
    return $details
}

# =============================================================================
# СИСТЕМА КЛАССИФИКАЦИИ БЕЗОПАСНОСТИ
# =============================================================================
function Get-RegistrySafetyLevel {
    param([string]$RegistryPath)
    
    # Паттерны безопасности
    $safetyPatterns = @{
        "Safe" = @(
            "*\SOFTWARE\$AppName*",
            "*\SOFTWARE\Autodesk\$AppName*", 
            "*\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*$AppName*",
            "*\SOFTWARE\WOW6432Node\$AppName*",
            "*\SOFTWARE\WOW6432Node\Autodesk\$AppName*",
            "HKCU:\SOFTWARE\$AppName*",
            "HKCU\SOFTWARE\Autodesk\$AppName*",
            "*\Software\$AppName\User Settings*",
            "*\Software\$AppName\Cache*",
            "*\Software\$AppName\Temp*",
            "*\Software\$AppName\Logs*"
        )
        "Caution" = @(
            "*\Classes\$AppName.*",
            "*\Classes\Applications\$AppName*", 
            "*\TypeLib\*$AppName*",
            "*\Interface\*$AppName*",
            "*\AppID\*$AppName*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.*$AppName*",
            "*\Explorer\RecentDocs\.*$AppName*",
            "*\Software\$AppName\Settings*",
            "*\Software\$AppName\Options*", 
            "*\Software\$AppName\Preferences*",
            "*\Software\$AppName\Profiles*"
        )
        "Dangerous" = @(
            "*\Microsoft\Windows NT\CurrentVersion*",
            "*\System\CurrentControlSet\*",
            "*\Classes\CLSID\*",
            "*\Classes\Interface\*", 
            "*\WOW6432Node\Classes\CLSID\*",
            "HKLM:\SAM*",
            "HKLM:\SECURITY*",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run*",
            "*\Policies\*",
            "*\Windows\CurrentVersion\Explorer\*",
            "*\Control Panel\*",
            "*\Software\$AppName\Services*",
            "*\Software\$AppName\Drivers*",
            "*\Software\Microsoft\Windows\CurrentVersion\App Paths\$AppName*"
        )
        "Critical" = @(
            "HKLM:\SYSTEM\*",
            "HKLM:\HARDWARE\*", 
            "HKLM:\COMPONENTS\*",
            "HKLM:\BCD*",
            "*\Microsoft\Cryptography\*",
            "*\Microsoft\SystemCertificates\*",
            "*\Microsoft\Windows Defender\*",
            "*\Microsoft\Security Center\*"
        )
    }
    
    # Сначала проверяем по существующим паттернам
    foreach ($level in $safetyPatterns.Keys) {
        if (Test-PathPattern -Path $RegistryPath -Patterns $safetyPatterns[$level]) {
            return $level
        }
    }
    
    # Для неизвестных путей используем оценку важности
    $keyDetails = Get-RegistryKeyDetails -RegistryPath $RegistryPath
    $score = $keyDetails.ImportanceScore
    
    if ($score -le $Script:Config.Safety.ScoreThresholds.Safe) { return "Safe" }
    elseif ($score -le $Script:Config.Safety.ScoreThresholds.Caution) { return "Caution" }
    elseif ($score -le $Script:Config.Safety.ScoreThresholds.Dangerous) { return "Dangerous" }
    else { return "Critical" }
}

function Get-SafetyLevelColor {
    param([string]$SafetyLevel)
    
    $colors = @{
        "Safe" = "Green"
        "Caution" = "Yellow" 
        "Dangerous" = "Red"
        "Critical" = "DarkRed"
        "Unknown" = "Gray"
    }
    
    return $colors[$SafetyLevel]
}

function Get-RecommendedAction {
    param([string]$RegistryPath)
    
    $safetyLevel = Get-RegistrySafetyLevel -RegistryPath $RegistryPath
    $keyDetails = Get-RegistryKeyDetails -RegistryPath $RegistryPath
    
    switch ($safetyLevel) {
        "Safe" { return "Безопасно для удаления" }
        "Caution" { return "Создать резервную копию перед удалением" }
        "Dangerous" { return "НЕ УДАЛЯТЬ - Высокая важность" }
        "Critical" { return "НЕ УДАЛЯТЬ - Критический системный ключ" }
        default { return "Требуется ручная проверка" }
    }
}

# =============================================================================
# ФУНКЦИИ ПОИСКА
# =============================================================================
function Get-RegistryHives {
    $hives = @("HKLM:", "HKCU:")
    
    try {
        if (Test-Path "HKU:\" -ErrorAction SilentlyContinue) {
            $hives += "HKU:"
        }
    } catch { Write-Warning "Раздел HKU: недоступен" }
    
    if ($IncludeClassesRoot) {
        try {
            if (Test-Path "HKCR:\" -ErrorAction SilentlyContinue) {
                $hives += "HKCR:"
            }
        } catch { Write-Warning "Раздел HKCR: недоступен" }
    }
    
    try {
        if (Test-Path "HKCC:\" -ErrorAction SilentlyContinue) {
            $hives += "HKCC:"
        }
    } catch { Write-Warning "Раздел HKCC: недоступен" }
    
    if ($IncludeUsers) {
        try {
            $userHives = Get-ChildItem "HKU:\" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notlike "*_Classes" }
            foreach ($userHive in $userHives) {
                $hives += "HKU:\$($userHive.PSChildName)"
            }
        } catch { Write-Warning "Не удалось получить список пользовательских разделов" }
    }
    
    return $hives | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path $_ -ErrorAction SilentlyContinue) }
}

function Get-RegistryValues {
    param([string]$Path)
    
    $values = @()
    
    try {
        if (Test-Path $Path -ErrorAction SilentlyContinue) {
            $key = Get-Item $Path -ErrorAction SilentlyContinue
            
            foreach ($valueName in $key.GetValueNames()) {
                try {
                    $valueData = $key.GetValue($valueName)
                    $valueType = $key.GetValueKind($valueName)
                    
                    $values += [PSCustomObject]@{
                        Path = $Path
                        Name = if ($valueName -eq "") { "(По умолчанию)" } else { $valueName }
                        Type = $valueType
                        Data = if ($valueData -is [array]) { ($valueData -join ", ") } else { $valueData }
                    }
                } catch { }
            }
        }
    } catch { }
	
    return $values
}

function Search-RegistryDeep {
    param(
        [string]$Path,
        [string]$SearchPattern,
        [int]$CurrentDepth = 0,
        [int]$MaxDepth = 10,
        [bool]$ExactMatch = $false,
        [int]$IterationCount = 0
    )
    
    $results = @()
    $IterationCount++
    
    # Управление памятью
    Invoke-MemoryManagement -IterationCount $IterationCount
    
    if ([string]::IsNullOrWhiteSpace($Path) -or $CurrentDepth -ge $MaxDepth) {
        return $results
    }
    
    # Пропускаем системные пути
    $skipPatterns = @("*\SAM*", "*\SECURITY*", "*\BCD*", "*\HARDWARE*")
    if (Test-PathPattern -Path $Path -Patterns $skipPatterns) {
        return $results
    }
    
    # Ограничение по времени выполнения
    if ($Global:ScriptStartTime -and (Get-Date) -gt $Global:ScriptStartTime.AddMinutes($Script:Config.Search.MaxExecutionTimeMinutes)) {
        return $results
    }
    
    try {
        if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) {
            return $results
        }
        
        $key = Get-Item $Path -ErrorAction SilentlyContinue
        if (-not $key) { return $results }
        
        # Поиск по пути
        $pathMatch = $false
        if ($ExactMatch) {
            if ($Path -match "\\$SearchPattern(\\|$)" -or $Path -match "\\$SearchPattern\.exe") {
                $pathMatch = $true
            }
        } else {
            if ($Path -like "*$SearchPattern*") {
                $pathMatch = $true
            }
        }
        
        if ($pathMatch) {
            $results += $Path
        }
        
        # Поиск в значениях
        $values = Get-RegistryValues -Path $Path
        foreach ($value in $values) {
            $valueMatch = $false
            if ($ExactMatch) {
                if ($value.Name -match "\b$SearchPattern\b" -or 
                    $value.Data -match "\b$SearchPattern\b" -or
                    $value.Data -like "*$SearchPattern.exe*") {
                    $valueMatch = $true
                }
            } else {
                if ($value.Name -like "*$SearchPattern*" -or 
                    $value.Data -like "*$SearchPattern*") {
                    $valueMatch = $true
                }
            }
            
            if ($valueMatch) {
                $results += $Path
                break
            }
        }
        
        # Рекурсивный поиск в подразделах
        try {
            $subKeys = Get-ChildItem $Path -ErrorAction Stop | Where-Object { 
                $_.PSChildName -notlike ".*" -and -not [string]::IsNullOrWhiteSpace($_.PSPath)
            }
            
            foreach ($subKey in $subKeys) {
                $subResults = Search-RegistryDeep -Path $subKey.PSPath -SearchPattern $SearchPattern -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth -ExactMatch $ExactMatch -IterationCount $IterationCount
                $results += $subResults
            }
        }
        catch {
            # Пропускаем недоступные подразделы
        }
    }
    catch {
        # Пропускаем проблемные разделы
    }
    
    return $results
}

# ====================================================================================================
# ОСТАЛЬНЫЕ ФУНКЦИИ

# =============================================================================
# ПОИСК И СКАНИРОВАНИЕ
# =============================================================================

function Search-RegistryAllHives {
    param(
        [string]$SearchPattern, 
        [int]$MaxDepth = 10,
        [bool]$ExactMatch = $false,
        [bool]$IncludeStandardPaths = $false,
        [bool]$UseMultiThreading = $false
    )
    
    $allResults = @()
    $hives = Get-RegistryHives
    
    $Logger.LogInfo("Поиск во всех разделах реестра...")
    $Logger.LogInfo("Режим поиска: $(if ($ExactMatch) { 'Точное соответствие' } else { 'Частичное соответствие' })")
    $Logger.LogInfo("Многопоточность: $(if ($UseMultiThreading) { 'Включена' } else { 'Выключена' })")
    
    # Поиск в стандартных расположениях
    if ($IncludeStandardPaths) {
        $Logger.LogInfo("Поиск в стандартных расположениях...")
        $standardResults = Search-StandardLocations -SearchAppName $SearchPattern
        $allResults += $standardResults
        $Logger.LogInfo("Найдено в стандартных расположениях: $($standardResults.Count)")
    }
    
    if ($hives.Count -eq 0) {
        $Logger.LogWarning("Нет доступных разделов реестра для поиска")
        return $allResults
    }
    
    # ВЫБОР МЕТОДА ПОИСКА
    if ($UseMultiThreading -and $hives.Count -ge 2) {
        $Logger.LogInfo("Использование многопоточного поиска...")
        $hiveResults = Search-RegistryParallel -Hives $hives -SearchPattern $SearchPattern -MaxDepth $MaxDepth -ExactMatch $ExactMatch
        $allResults += $hiveResults
    }
    else {
        $Logger.LogInfo("Использование однопоточного поиска...")
        foreach ($hive in $hives) {
            try {
                if (-not [string]::IsNullOrWhiteSpace($hive) -and (Test-Path $hive -ErrorAction SilentlyContinue)) {
                    $Logger.LogInfo("Обработка раздела: $hive")
                    $hiveResults = Search-RegistryDeep -Path $hive -SearchPattern $SearchPattern -MaxDepth $MaxDepth -ExactMatch $ExactMatch
                    $allResults += $hiveResults
                    $Logger.LogInfo("Найдено в $hive`: $($hiveResults.Count)")
                }
            }
            catch {
                $Logger.LogWarning("Ошибка обработки раздела $hive : $($_.Exception.Message)")
            }
        }
    }
    
    $Logger.LogSuccess("Поиск завершен. Всего найдено: $($allResults.Count) записей")
    return $allResults
}

function Search-RegistryParallel {
    param(
        [array]$Hives,
        [string]$SearchPattern, 
        [int]$MaxDepth = 10,
        [bool]$ExactMatch = $false
    )
    
    # Автоматическое определение оптимального количества потоков
    $cpuCores = [Environment]::ProcessorCount
    $optimalThreads = [math]::Min($Hives.Count, [math]::Max(2, $cpuCores - 1))
    
    $Logger.LogInfo("Запуск многопоточного поиска...")
    $Logger.LogInfo("Разделы: $($Hives.Count)")
    $Logger.LogInfo("Потоки: $optimalThreads")
    $Logger.LogInfo("Глубина поиска: $MaxDepth")
    
    $results = Start-ThreadedRegistrySearch -Hives $Hives -SearchPattern $SearchPattern -MaxDepth $MaxDepth -ExactMatch $ExactMatch -MaxThreads $optimalThreads
    
    return @($results) | Sort-Object | Get-Unique
}

function Search-StandardLocations {
    param([string]$SearchAppName)
    
    $standardResults = @()
    $standardPaths = @(
        "HKCU:\Software\$SearchAppName",
        "HKLM:\SOFTWARE\$SearchAppName", 
        "HKLM:\SOFTWARE\WOW6432Node\$SearchAppName",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*$SearchAppName*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*$SearchAppName*",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$SearchAppName*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\$SearchAppName*",
        "HKLM:\SOFTWARE\Classes\Applications\$SearchAppName*",
        "HKCU:\Software\Classes\Applications\$SearchAppName*"
    )
    
    Write-Host "Поиск в стандартных расположениях..." -ForegroundColor Cyan
    
    foreach ($pathPattern in $standardPaths) {
        try {
            if (Test-Path $pathPattern -ErrorAction SilentlyContinue) {
                $resolvedPaths = Get-Item $pathPattern -ErrorAction SilentlyContinue
                foreach ($resolvedPath in $resolvedPaths) {
                    $standardResults += $resolvedPath.PSPath
                    Write-Host "  Найдено: $($resolvedPath.PSPath)" -ForegroundColor Green
                }
            }
        }
        catch {
            # Игнорируем недоступные пути
        }
    }
    
    return $standardResults
}

function Start-ThreadedRegistrySearch {
    param(
        [array]$Hives,
        [string]$SearchPattern, 
        [int]$MaxDepth = 10,
        [bool]$ExactMatch = $false,
        [int]$MaxThreads = 5
    )
    
    $allResults = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
    $runspacePool = $null
    $jobs = @()

    try {
        $Logger.LogInfo("Запуск многопоточного поиска с $MaxThreads потоками...")
        
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
        $runspacePool.Open()
        
        # Создаем задания для каждого раздела реестра
        foreach ($hive in $Hives) {
            $powerShell = [powershell]::Create()
            $powerShell.RunspacePool = $runspacePool
            
            # Добавляем скрипт блока
            [void]$powerShell.AddScript({
                param($HivePath, $Pattern, $Depth, $IsExactMatch)
                
                function Search-RegistryDeepThreaded {
                    param(
                        [string]$Path,
                        [string]$SearchPattern,
                        [int]$CurrentDepth = 0,
                        [int]$MaxDepth = 10,
                        [bool]$ExactMatch = $false
                    )
                    
                    $threadResults = @()
                    
                    if ($CurrentDepth -ge $MaxDepth -or [string]::IsNullOrWhiteSpace($Path)) {
                        return $threadResults
                    }
                    
                    try {
                        if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) {
                            return $threadResults
                        }
                        
                        $key = Get-Item $Path -ErrorAction SilentlyContinue
                        if (-not $key) { return $threadResults }
                        
                        # Проверка пути
                        $pathMatch = $false
                        if ($ExactMatch) {
                            if ($Path -match "\\$SearchPattern(\\|$)" -or $Path -match "\\$SearchPattern\.exe") {
                                $pathMatch = $true
                            }
                        } else {
                            if ($Path -like "*$SearchPattern*") {
                                $pathMatch = $true
                            }
                        }
                        
                        if ($pathMatch) {
                            $threadResults += $Path
                        }
                        
                        # Проверка значений
                        try {
                            $values = @()
                            foreach ($valueName in $key.GetValueNames()) {
                                try {
                                    $valueData = $key.GetValue($valueName)
                                    $valueMatch = $false
                                    
                                    if ($ExactMatch) {
                                        if ($valueName -match "\b$SearchPattern\b" -or 
                                            $valueData -match "\b$SearchPattern\b" -or
                                            $valueData -like "*$SearchPattern.exe*") {
                                            $valueMatch = $true
                                        }
                                    } else {
                                        if ($valueName -like "*$SearchPattern*" -or 
                                            $valueData -like "*$SearchPattern*") {
                                            $valueMatch = $true
                                        }
                                    }
                                    
                                    if ($valueMatch) {
                                        $threadResults += $Path
                                        break
                                    }
                                }
                                catch {
                                    # Пропускаем проблемные значения
                                }
                            }
                        }
                        catch {
                            # Пропускаем разделы с ошибками чтения значений
                        }
                        
                        # Рекурсивный поиск в подразделах
                        try {
                            $subKeys = Get-ChildItem $Path -ErrorAction Stop | 
                                      Where-Object { $_.PSChildName -notlike ".*" -and -not [string]::IsNullOrWhiteSpace($_.PSPath) }
                            
                            foreach ($subKey in $subKeys) {
                                $subResults = Search-RegistryDeepThreaded -Path $subKey.PSPath -SearchPattern $SearchPattern -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth -ExactMatch $ExactMatch
                                $threadResults += $subResults
                            }
                        }
                        catch {
                            # Пропускаем недоступные подразделы
                        }
                    }
                    catch {
                        # Пропускаем проблемные разделы
                    }
                    
                    return $threadResults
                }
                
                # Основная логика потока
                $hiveResults = @()
                try {
                    if (-not [string]::IsNullOrWhiteSpace($HivePath) -and (Test-Path $HivePath -ErrorAction SilentlyContinue)) {
                        $hiveResults = Search-RegistryDeepThreaded -Path $HivePath -SearchPattern $Pattern -MaxDepth $Depth -ExactMatch $IsExactMatch
                    }
                }
                catch {
                    # Логируем ошибки в потоке
                    $errorMsg = $_.Exception.Message
                    try {
                        # Простой вывод ошибки без цветов для потоков
                        "[THREAD ERROR] $HivePath : $errorMsg" | Out-File -FilePath "thread_errors.log" -Append -Encoding UTF8
                    }
                    catch {
                        # Игнорируем ошибки логирования в потоках
                    }
                }
                
                return $hiveResults
            })
            
            # Добавляем параметры
            [void]$powerShell.AddParameter("HivePath", $hive)
            [void]$powerShell.AddParameter("Pattern", $SearchPattern)
            [void]$powerShell.AddParameter("Depth", $MaxDepth)
            [void]$powerShell.AddParameter("IsExactMatch", $ExactMatch)
            
            # Запускаем асинхронно
            $job = @{
                PowerShell = $powerShell
                Handle = $powerShell.BeginInvoke()
                Hive = $hive
            }
            $jobs += $job
        }
        
        # Ожидаем завершения и собираем результаты
        $completedCount = 0
        $totalJobs = $jobs.Count
        
        while ($jobs.Count -gt 0) {
            $completedJobs = @()
            
            foreach ($job in $jobs) {
                if ($job.Handle.IsCompleted) {
                    try {
                        $results = $job.PowerShell.EndInvoke($job.Handle)
                        foreach ($result in $results) {
                            $allResults.Add($result)
                        }
                        
                        $completedCount++
                        $percentComplete = [math]::Round(($completedCount / $totalJobs) * 100, 1)
                        
                        Write-Progress -Activity "Многопоточный поиск" `
                                       -Status "Завершено: $completedCount из $totalJobs ($percentComplete%)" `
                                       -PercentComplete $percentComplete `
                                       -CurrentOperation "Обработан раздел: $($job.Hive)"
                        
                        $completedJobs += $job
                    }
                    catch {
                        $Logger.LogWarning("Ошибка в потоке для $($job.Hive): $($_.Exception.Message)")
                        $completedJobs += $job
                    }
                    finally {
                        $job.PowerShell.Dispose()
                    }
                }
            }
            
            # Удаляем завершенные задания
            foreach ($completedJob in $completedJobs) {
                $jobs = $jobs | Where-Object { $_.Handle -ne $completedJob.Handle }
            }
            
            # Небольшая пауза для уменьшения нагрузки на CPU
            if ($jobs.Count -gt 0) {
                Start-Sleep -Milliseconds 100
            }
        }
        
        Write-Progress -Activity "Многопоточный поиск" -Completed
        $Logger.LogSuccess("Многопоточный поиск завершен. Найдено записей: $($allResults.Count)")
    }
    catch {
        $Logger.LogError("Критическая ошибка в многопоточном поиске: $($_.Exception.Message)")
        throw
    }
    finally {
        # ОБЯЗАТЕЛЬНОЕ освобождение ресурсов
        try {
            if ($runspacePool) {
                $runspacePool.Close()
                $runspacePool.Dispose()
                $Logger.LogDebug("Пул потоков освобожден")
            }
        }
        catch {
            $Logger.LogWarning("Ошибка при освобождении пула потоков: $($_.Exception.Message)")
        }
        
        # Освобождаем оставшиеся задания
        foreach ($job in $jobs) {
            try {
                if ($job.PowerShell -and $job.PowerShell -is [System.IDisposable]) {
                    $job.PowerShell.Dispose()
                }
            }
            catch {
                # Игнорируем ошибки при освобождении
            }
        }
        
        # Принудительная сборка мусора
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
    
    return $allResults | Sort-Object | Get-Unique
}

function Test-IsFalsePositive {
    param(
        [string]$RegistryPath,
        [string]$ValueName, 
        [object]$ValueData,
        [string]$SearchPattern
    )
    
	# ПЕРВОЕ - ПРИМЕНИТЬ СТРОГУЮ ФИЛЬТРАЦИЮ ДЛЯ СИСТЕМНЫХ ПУТЕЙ
    if (Test-SystemPathWithStrictFilter -RegistryPath $RegistryPath -ValueName $ValueName -ValueData $ValueData -SearchPattern $SearchPattern) {
        return $true
    }
    
	if ($RegistryPath -like "*NotifyIconSettings*") {
		$dataString = if ($ValueData -is [array]) { 
			$ValueData -join " " 
		} else { 
			$ValueData.ToString() 
		}
		
		# Для NotifyIconSettings проверяем только ExecutablePath
		if ($ValueName -eq "ExecutablePath" -and $dataString -match "[\\:]$SearchPattern\.exe") {
			return $false  # Это валидное совпадение
		}
		elseif ($ValueName -ne "ExecutablePath") {
			return $true   # Это ложное срабатывание
		}
	}

    # Расширенный список системных паттернов
    $systemPatterns = @(
        "*\Windows\*",
        "*\Microsoft\*", 
        "*\System32\*",
        "*\SysWOW64\*",
        "*\Classes\*", 
        "*\CloudStore\*",
        "*\IrisService\*",
        "*\Policy\*",
        "*\GroupPolicy\*",
        "*\Edge\*",
        "*\Chrome\*",
        "*\Browser\*"
    )
    
    # Проверка на временные/кэшированные данные
    $cachePatterns = @(
        "*\Cache*",
        "*\Temp*", 
        "*\Logs*",
        "*\History*",
        "*\Recent*",
        "*\Temporary*"
    )
    
    # Если путь системный И данные не содержат точного совпадения
    foreach ($pattern in $systemPatterns) {
        if ($RegistryPath -like $pattern) {
            $dataString = if ($ValueData -is [array]) { 
                $ValueData -join " " 
            } else { 
                $ValueData.ToString() 
            }
            
            # Требуем более строгого соответствия для системных путей
            if ($dataString -notmatch "\\$SearchPattern\.exe" -and 
                $ValueName -notmatch "\\$SearchPattern\.exe" -and
                $dataString -notmatch "\\$SearchPattern\\" -and
                $RegistryPath -notmatch "\\$SearchPattern\\") {
                return $true
            }
        }
    }
    
    # Для кэшированных данных требуем точного соответствия
    foreach ($pattern in $cachePatterns) {
        if ($RegistryPath -like $pattern -and $ExactMatch) {
            if ($ValueData -notmatch "\\$SearchPattern\.exe") {
                return $true
            }
        }
    }
    
    return $false
}

function Test-SystemPathWithStrictFilter {
    param(
        [string]$RegistryPath, 
        [string]$ValueName,
        [object]$ValueData,
        [string]$SearchPattern
    )
    
    $systemPaths = @(
        "*\MuiCache*",
        "*\NotifyIconSettings*", 
        "*\RecentDocs*",
        "*\CloudStore*",
        "*\TileDataLayer*",
        "*\AppCache*"
    )
    
    foreach ($sysPath in $systemPaths) {
        if ($RegistryPath -like $sysPath) {
            Write-Debug "Applying strict filter for system path: $RegistryPath"
            
            # Для системных путей требовать точного соответствия в данных
            $dataString = if ($ValueData -is [array]) { 
                $ValueData -join " " 
            } else { 
                $ValueData.ToString() 
            }
            
            # СТРОГИЕ УСЛОВИЯ ДЛЯ СИСТЕМНЫХ ПУТЕЙ
            $isValidMatch = $false
            
            # 1. Имя значения содержит полный путь к EXE
            if ($ValueName -match "[\\:]$SearchPattern\.exe") {
                $isValidMatch = $true
                Write-Debug "System path VALID - ValueName match: $ValueName"
            }
            # 2. Данные содержат полный путь к EXE
            elseif ($dataString -match "[\\:]$SearchPattern\.exe") {
                $isValidMatch = $true
                Write-Debug "System path VALID - Data match: $dataString"
            }
            # 3. Метаданные приложения
            elseif (($ValueName -like "*FriendlyAppName*" -or $ValueName -like "*ApplicationCompany*") -and 
                    $dataString -like "*$SearchPattern*") {
                $isValidMatch = $true
                Write-Debug "System path VALID - App metadata: $ValueName"
            }
            # 4. Для NotifyIconSettings - только ExecutablePath
            elseif ($RegistryPath -like "*NotifyIconSettings*" -and $ValueName -eq "ExecutablePath" -and 
                    $dataString -match "[\\:]$SearchPattern\.exe") {
                $isValidMatch = $true
                Write-Debug "System path VALID - NotifyIcon ExecutablePath"
            }
            
            # Если не прошло строгую проверку - это ложное срабатывание
            if (-not $isValidMatch) {
                Write-Debug "System path FALSE POSITIVE - Path: $RegistryPath, Name: $ValueName"
                return $true
            }
            
            Write-Debug "System path VALID MATCH - Path: $RegistryPath"
            return $false
        }
    }
    
    # Не системный путь - пропускаем обычную фильтрацию
    return $false
}

# =============================================================================
# АНАЛИЗ И КЛАССИФИКАЦИЯ
# =============================================================================

function Analyze-COMComponent {
    param([string]$RegistryPath)
    
    $programs = @()
    $details = @()
    
    try {
        # Извлекаем CLSID, TypeLib ID или Interface ID
        if ($RegistryPath -match "CLSID\\\{([^}]+)\}") {
            $clsid = $Matches[1]
            $details += "COM компонент (CLSID: $clsid)"
            
            # Проверяем InProcServer32
            $inprocPath = "HKCR:\CLSID\{$clsid}\InProcServer32"
            if (Test-Path $inprocPath) {
                $server = Get-ItemProperty -Path $inprocPath -Name "(default)" -ErrorAction SilentlyContinue
                if ($server -and $server."(default)") {
                    $programName = Get-FileDescription -FilePath $server."(default)"
                    if ($programName) {
                        $programs += $programName
                    }
                }
            }
            
            # Проверяем LocalServer32
            $localPath = "HKCR:\CLSID\{$clsid}\LocalServer32"
            if (Test-Path $localPath) {
                $server = Get-ItemProperty -Path $localPath -Name "(default)" -ErrorAction SilentlyContinue
                if ($server -and $server."(default)") {
                    $programName = Get-FileDescription -FilePath $server."(default)"
                    if ($programName) {
                        $programs += $programName
                    }
                }
            }
        }
        
        if ($RegistryPath -match "TypeLib\\\{([^}]+)\}") {
            $libid = $Matches[1]
            $details += "Библиотека типов (LibID: $libid)"
        }
        
        if ($RegistryPath -match "Interface\\\{([^}]+)\}") {
            $iid = $Matches[1]
            $details += "COM интерфейс (IID: $iid)"
        }
    }
    catch {
        # Игнорируем ошибки доступа
    }
    
    return @{
        Programs = $programs
        Details = $details
    }
}

function Analyze-ContextMenu {
    param([string]$RegistryPath)
    
    $programs = @()
    $details = @()
    
    try {
        if ($RegistryPath -like "*\ContextMenuHandlers\*") {
            $handlerName = $RegistryPath -replace ".*ContextMenuHandlers\\", ""
            $details += "Обработчик контекстного меню: $handlerName"
            
            $clsid = Get-ItemProperty -Path $RegistryPath -Name "(default)" -ErrorAction SilentlyContinue
            if ($clsid -and $clsid."(default)" -and $clsid."(default)" -match "\{[^}]+\}") {
                $programName = Get-COMComponentName -CLSID $clsid."(default)"
                if ($programName) {
                    $programs += $programName
                }
            }
        }
        
        if ($RegistryPath -like "*\shell\\*") {
            $verb = $RegistryPath -replace ".*shell\\", "" -replace "\\command.*", ""
            $details += "Действие в меню: $verb"
            
            $commandPath = "$RegistryPath\command"
            if (Test-Path $commandPath) {
                $command = Get-ItemProperty -Path $commandPath -Name "(default)" -ErrorAction SilentlyContinue
                if ($command -and $command."(default)") {
                    $exePath = ($command."(default)" -split '"')[1]
                    if ($exePath -and (Test-Path $exePath)) {
                        $programName = Get-FileDescription -FilePath $exePath
                        if ($programName) {
                            $programs += $programName
                        }
                    }
                }
            }
        }
    }
    catch {
        # Игнорируем ошибки доступа
    }
    
    return @{
        Programs = $programs
        Details = $details
    }
}

function Analyze-ProtocolHandler {
    param([string]$RegistryPath)
    
    $programs = @()
    $details = @()
    
    try {
        if ($RegistryPath -match "PROTOCOLS\\Handler\\([^\\]+)") {
            $protocol = $Matches[1]
            $details += "Обработчик протокола: $protocol"
            
            $handlerPath = "HKCR:\PROTOCOLS\Handler\$protocol"
            if (Test-Path $handlerPath) {
                $class = Get-ItemProperty -Path $handlerPath -Name "CLSID" -ErrorAction SilentlyContinue
                if ($class -and $class.CLSID) {
                    $clsidPath = "HKCR:\CLSID\$($class.CLSID)"
                    $programName = Get-COMComponentName -CLSID $class.CLSID
                    if ($programName) {
                        $programs += $programName
                    }
                }
            }
        }
    }
    catch {
        # Игнорируем ошибки доступа
    }
    
    return @{
        Programs = $programs
        Details = $details
    }
}

function Extract-FileExtension {
    param([string]$Path)
    
    # Извлекаем расширение файла из пути реестра
    $patterns = @(
        "\.([^\.\\]+)\\",
        "FileExts\\\.([^\.\\]+)",
        "Classes\\\.([^\.\\]+)"
    )
    
    foreach ($pattern in $patterns) {
        if ($Path -match $pattern) {
            return ".$($Matches[1])"
        }
    }
    
    return $null
}

function Find-COMReferences {
    param([string]$CLSID)
    
    $references = @()
    try {
        # Поиск ссылок на COM компонент в реестре
        $searchPaths = @(
            "HKCR:\*\shell\*\command",
            "HKCR:\*\shellex\ContextMenuHandlers\*",
            "HKCR:\Protocols\Handler\*",
            "HKLM:\SOFTWARE\Classes\*\shellex\*"
        )
        
        foreach ($searchPath in $searchPaths) {
            if (Test-Path $searchPath) {
                $items = Get-ChildItem $searchPath -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    $clsidValue = Get-ItemProperty -Path $item.PSPath -Name "(default)" -ErrorAction SilentlyContinue
                    if ($clsidValue -and $clsidValue."(default)" -like "*$CLSID*") {
                        $references += "COM Reference: $($item.PSPath)"
                    }
                }
            }
        }
    }
    catch {
        # Игнорируем ошибки
    }
    
    return $references
}

function Find-ServiceDependencies {
    param([string]$ServiceName)
    
    $dependencies = @()
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            $dependencies += "Служба: $($service.DisplayName)"
            
            # Проверяем зависимости службы
            $serviceObj = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($serviceObj -and $serviceObj.Dependencies) {
                $dependencies += $serviceObj.Dependencies
            }
        }
    }
    catch {
        # Игнорируем ошибки
    }
    
    return $dependencies
}

function Get-AffectedProgramsAnalysis {
    param([string]$RegistryPath)
    
    $affectedPrograms = @()
    $analysisDetails = @()
    
    # Анализ файловых ассоциаций
    if ($RegistryPath -like "*\Classes\*" -or $RegistryPath -like "*\FileExts\*") {
        $fileExt = Extract-FileExtension -Path $RegistryPath
        if ($fileExt) {
            $associatedPrograms = Get-ProgramsForFileExtension -FileExtension $fileExt
            $affectedPrograms += $associatedPrograms
            $analysisDetails += "Затрагивает ассоциации файлов: $fileExt"
        }
    }
    
    # ДОБАВИТЬ проверку на доступность путей перед анализом COM
    try {
        # Анализ COM компонентов
        if ($RegistryPath -like "*\CLSID\*" -or $RegistryPath -like "*\TypeLib\*" -or $RegistryPath -like "*\Interface\*") {
            $comAnalysis = Analyze-COMComponent -RegistryPath $RegistryPath
            $affectedPrograms += $comAnalysis.Programs
            $analysisDetails += $comAnalysis.Details
        }
        
        # Анализ протоколов и обработчиков
        if ($RegistryPath -like "*\Protocols\*" -or $RegistryPath -like "*\Shell\*") {
            $protocolAnalysis = Analyze-ProtocolHandler -RegistryPath $RegistryPath
            $affectedPrograms += $protocolAnalysis.Programs
            $analysisDetails += $protocolAnalysis.Details
        }
        
        # Анализ контекстного меню
        if ($RegistryPath -like "*\shell\*" -or $RegistryPath -like "*\ContextMenuHandlers\*") {
            $contextMenuAnalysis = Analyze-ContextMenu -RegistryPath $RegistryPath
            $affectedPrograms += $contextMenuAnalysis.Programs
            $analysisDetails += $contextMenuAnalysis.Details
        }
    }
    catch {
        # Игнорируем ошибки при анализе
        Write-Debug "Ошибка анализа пути: $RegistryPath"
    }
    
    # Удаляем дубликаты и пустые значения
    $affectedPrograms = $affectedPrograms | Where-Object { $_ -and $_.Trim() -ne "" } | Sort-Object | Get-Unique
    $analysisDetails = $analysisDetails | Where-Object { $_ -and $_.Trim() -ne "" }
    
    return @{
        Programs = $affectedPrograms
        Details = $analysisDetails
    }
}

function Get-COMComponentName {
    param([string]$CLSID)
    
    try {
        $clsidPath = "HKCR:\CLSID\$CLSID"
        if (Test-Path $clsidPath) {
            $description = Get-ItemProperty -Path $clsidPath -Name "(default)" -ErrorAction SilentlyContinue
            if ($description -and $description."(default)") {
                return $description."(default)"
            }
        }
    }
    catch {
        # Игнорируем ошибки доступа
    }
    
    return $null
}

function Get-EnhancedSafetyDescription {
    param([string]$SafetyLevel, [string]$RegistryPath)
    
    $baseDescriptions = @{
        "Safe" = "БЕЗОПАСНО - Можно удалять: ключи, специфичные для приложения"
        "Caution" = "ОСТОРОЖНО - Условно безопасно: могут затрагивать другие программы" 
        "Dangerous" = "ОПАСНО - Не рекомендуется: системные или общие ключи"
        "Critical" = "КРИТИЧЕСКИ - Никогда не удалять: системные ключи"
        "Unknown" = "НЕИЗВЕСТНО - Требуется дополнительная проверка"
    }
    
    $baseDescription = $baseDescriptions[$SafetyLevel]
    
    # Для "осторожных" путей добавляем анализ затронутых программ
    if ($SafetyLevel -eq "Caution") {
        $analysis = Get-AffectedProgramsAnalysis -RegistryPath $RegistryPath
        
        if ($analysis.Programs.Count -gt 0) {
            $affectedPrograms = $analysis.Programs -join ", "
            $baseDescription += "`n   Затронутые программы: $affectedPrograms"
        }
        
        if ($analysis.Details.Count -gt 0) {
            $analysisDetails = $analysis.Details -join "; "
            $baseDescription += "`n   Детали: $analysisDetails"
        }
    }
    
    return $baseDescription
}

function Get-FileDescription {
    param([string]$FilePath)
    
    $shell = $null
    $folder = $null
    $file = $null
    
    try {
        # Проверяем существование файла
        if (-not (Test-Path $FilePath -ErrorAction SilentlyContinue)) {
            Write-Debug "Файл не существует: $FilePath"
            return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        }
        
        # Получаем информацию о файле
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if (-not $fileInfo) {
            Write-Debug "Не удалось получить информацию о файле: $FilePath"
            return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        }
        
        # Проверяем, что это файл (а не папка)
        if ($fileInfo.PSIsContainer) {
            Write-Debug "Указанный путь является папкой: $FilePath"
            return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        }
        
        # Создаем COM объекты
        $shell = New-Object -ComObject Shell.Application
        if (-not $shell) {
            Write-Debug "Не удалось создать COM объект Shell.Application"
            return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        }
        
        # Получаем папку
        $folder = $shell.Namespace($fileInfo.DirectoryName)
        if (-not $folder) {
            Write-Debug "Не удалось получить папку: $($fileInfo.DirectoryName)"
            return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        }
        
        # Получаем файл
        $file = $folder.ParseName($fileInfo.Name)
        if (-not $file) {
            Write-Debug "Не удалось получить файл: $($fileInfo.Name)"
            return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        }
        
        # Получаем описание файла (2 - File description)
        $description = $folder.GetDetailsOf($file, 2)
        
        # Если описание пустое, возвращаем имя файла без расширения
        if ([string]::IsNullOrWhiteSpace($description)) {
            Write-Debug "Описание файла пустое: $FilePath"
            return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        }
        
        return $description.Trim()
    }
    catch [System.Management.Automation.MethodInvocationException] {
        Write-Debug "COM ошибка при получении описания файла: $FilePath - $($_.Exception.Message)"
        return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    }
    catch [System.Runtime.InteropServices.COMException] {
        Write-Debug "COM исключение при получении описания файла: $FilePath - $($_.Exception.Message)"
        return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    }
    catch [System.UnauthorizedAccessException] {
        Write-Debug "Ошибка доступа к файлу: $FilePath - $($_.Exception.Message)"
        return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    }
    catch [System.IO.IOException] {
        Write-Debug "IO ошибка при доступе к файлу: $FilePath - $($_.Exception.Message)"
        return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    }
    catch {
        Write-Debug "Общая ошибка при получении описания файла: $FilePath - $($_.Exception.Message)"
        return [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    }
    finally {
        # ОБЯЗАТЕЛЬНОЕ освобождение COM объектов в обратном порядке создания
        try {
            if ($file) { 
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($file) | Out-Null 
                $file = $null
            }
        }
        catch {
            # Игнорируем ошибки при освобождении
        }
        
        try {
            if ($folder) { 
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($folder) | Out-Null 
                $folder = $null
            }
        }
        catch {
            # Игнорируем ошибки при освобождении
        }
        
        try {
            if ($shell) { 
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null 
                $shell = $null
            }
        }
        catch {
            # Игнорируем ошибки при освобождении
        }
        
        # Принудительная сборка мусора для COM объектов
        try {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        catch {
            # Игнорируем ошибки сборки мусора
        }
    }
}

function Get-ProgramsForFileExtension {
    param([string]$FileExtension)
    
    $programs = @()
    
    try {
        # Ищем связанные программы через реестр
        $assocKey = "HKCR:\$FileExtension"
        if (Test-Path $assocKey) {
            $progId = Get-ItemProperty -Path $assocKey -Name "(default)" -ErrorAction SilentlyContinue
            if ($progId -and $progId."(default)") {
                $programs += $progId."(default)"
                
                # Получаем описание программы
                $progIdKey = "HKCR:\$($progId.'(default)')"
                if (Test-Path $progIdKey) {
                    $description = Get-ItemProperty -Path $progIdKey -Name "(default)" -ErrorAction SilentlyContinue
                    if ($description -and $description."(default)") {
                        $programs += $description."(default)"
                    }
                }
            }
        }
        
        # Проверяем OpenWithProgids
        $openWithKey = "$assocKey\OpenWithProgids"
        if (Test-Path $openWithKey) {
            $openWithProgids = Get-ItemProperty -Path $openWithKey -ErrorAction SilentlyContinue
            if ($openWithProgids) {
                $programs += $openWithProgids.PSObject.Properties | 
                    Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" } | 
                    Select-Object -ExpandProperty Name
            }
        }
    }
    catch {
        # Игнорируем ошибки доступа
    }
    
    return $programs
}

function Get-RegistryDependencies {
    param([string]$RegistryPath)
    
    $dependencies = @()
    
    # Анализ COM зависимостей
    if ($RegistryPath -like "*\CLSID\*") {
        $clsid = [System.IO.Path]::GetFileName($RegistryPath)
        $dependencies += Find-COMReferences -CLSID $clsid
    }
    
    # Анализ зависимостей служб
    if ($RegistryPath -like "*\Services\*") {
        $serviceName = [System.IO.Path]::GetFileName($RegistryPath)
        $dependencies += Find-ServiceDependencies -ServiceName $serviceName
    }
    
    return $dependencies
}

# =============================================================================
# ЭКСПОРТ И ОТЧЕТНОСТЬ
# =============================================================================

function ConvertTo-RegPath {
    param([string]$PsPath)
    
    $regPath = $PsPath -replace "^Microsoft\.PowerShell\.Core\\Registry::", ""
    $regPath = $regPath -replace "^HKCU\\", "HKEY_CURRENT_USER\"
    $regPath = $regPath -replace "^HKLM\\", "HKEY_LOCAL_MACHINE\"
    $regPath = $regPath -replace "^HKU\\", "HKEY_USERS\"
    $regPath = $regPath -replace "^HKCR\\", "HKEY_CLASSES_ROOT\"
    $regPath = $regPath -replace "^HKCC\\", "HKEY_CURRENT_CONFIG\"
    
    return $regPath
}

function Export-RegistryKeys {
    param([array]$RegistryPaths, [string]$ExportFile)
    
    try {
        $exportContent = "Windows Registry Editor Version 5.00`n`n"
        
        foreach ($path in $RegistryPaths) {
            $regPath = ConvertTo-RegPath -PsPath $path
            $exportContent += "[$regPath]`n"
            
            $values = Get-RegistryValues -Path $path
            
            foreach ($value in $values) {
                # Нужно экранировать специальные символы в .reg файле
                $escapedData = $value.Data -replace '"', '\"'
                if ($value.Name -eq "(По умолчанию)") {
                    $exportContent += "@=`"$escapedData`"`n"
                } else {
                    $exportContent += "`"$value.Name`"=`"$escapedData`"`n"
                }
            }
            $exportContent += "`n"
        }
        
        # ДОБАВИТЬ: сохранение файла
        $exportContent | Out-File -FilePath $ExportFile -Encoding Unicode
        Write-Host "Экспорт реестра сохранен в: $ExportFile" -ForegroundColor Green
    }
    catch {
        Write-Error "Ошибка экспорта реестра: $($_.Exception.Message)"
    }
}

function New-EnhancedReport {
    param(
        [array]$Results, 
        [array]$Values,
        [string]$OutputFile,
        [string]$AppName,
        [int]$MaxDepth
    )
    
    $stringBuilder = [System.Text.StringBuilder]::new()
    
    # ЗАГОЛОВОК ОТЧЕТА
    [void]$stringBuilder.AppendLine("=" * 80)
    [void]$stringBuilder.AppendLine("РАСШИРЕННЫЙ ОТЧЕТ ПОИСКА ЗАПИСЕЙ РЕЕСТРА")
    [void]$stringBuilder.AppendLine("=" * 80)
    [void]$stringBuilder.AppendLine()
    
    # ОСНОВНАЯ ИНФОРМАЦИЯ
    [void]$stringBuilder.AppendLine("ОСНОВНАЯ ИНФОРМАЦИЯ:")
    [void]$stringBuilder.AppendLine("-" * 40)
    [void]$stringBuilder.AppendLine("Приложение: $AppName")
    [void]$stringBuilder.AppendLine("Время создания: $(Get-Date)")
    [void]$stringBuilder.AppendLine("Максимальная глубина поиска: $MaxDepth")
    [void]$stringBuilder.AppendLine("Найдено разделов: $($Results.Count)")
    [void]$stringBuilder.AppendLine("Найдено значений: $($Values.Count)")
    [void]$stringBuilder.AppendLine()
    
    # СТАТИСТИКА ПО УРОВНЯМ БЕЗОПАСНОСТИ
    $groupedResults = $Results | Group-Object SafetyLevel
    $safeCount = ($Results | Where-Object { $_.SafetyLevel -eq "Safe" }).Count
    $cautionCount = ($Results | Where-Object { $_.SafetyLevel -eq "Caution" }).Count
    $dangerousCount = ($Results | Where-Object { $_.SafetyLevel -eq "Dangerous" }).Count
    $criticalCount = ($Results | Where-Object { $_.SafetyLevel -eq "Critical" }).Count
    $unknownCount = ($Results | Where-Object { $_.SafetyLevel -eq "Unknown" }).Count
    
    [void]$stringBuilder.AppendLine("СТАТИСТИКА ПО УРОВНЯМ БЕЗОПАСНОСТИ:")
    [void]$stringBuilder.AppendLine("-" * 40)
    foreach ($group in $groupedResults | Sort-Object Name) {
        $percentage = [math]::Round(($group.Count / $Results.Count) * 100, 2)
        [void]$stringBuilder.AppendLine("$($group.Name): $($group.Count) записей ($percentage%)")
    }
    [void]$stringBuilder.AppendLine()
    
    # СВОДКА БЕЗОПАСНОСТИ
    [void]$stringBuilder.AppendLine("СВОДКА БЕЗОПАСНОСТИ:")
    [void]$stringBuilder.AppendLine("-" * 40)
    [void]$stringBuilder.AppendLine("✓ Безопасных для удаления: $safeCount")
    [void]$stringBuilder.AppendLine("⚠ Требуют проверки: $cautionCount")
    [void]$stringBuilder.AppendLine("✗ Опасных записей: $($dangerousCount + $criticalCount)")
    [void]$stringBuilder.AppendLine("? Неизвестных записей: $unknownCount")
    [void]$stringBuilder.AppendLine()
    
    # ОБЩИЕ РЕКОМЕНДАЦИИ
    [void]$stringBuilder.AppendLine("ОБЩИЕ РЕКОМЕНДАЦИИ:")
    [void]$stringBuilder.AppendLine("-" * 40)
    if ($safeCount -gt 0) {
        [void]$stringBuilder.AppendLine("• Можно безопасно удалить $safeCount записей (уровень 'Safe')")
    }
    if ($cautionCount -gt 0) {
        [void]$stringBuilder.AppendLine("• Проверьте перед удалением $cautionCount записей (уровень 'Caution')")
    }
    if ($dangerousCount -gt 0 -or $criticalCount -gt 0) {
        [void]$stringBuilder.AppendLine("• НЕ УДАЛЯЙТЕ $($dangerousCount + $criticalCount) опасных записей без крайней необходимости")
    }
    if ($unknownCount -gt 0) {
        [void]$stringBuilder.AppendLine("• Требуется ручная проверка $unknownCount неизвестных записей")
    }
    [void]$stringBuilder.AppendLine()
    
    # АНАЛИЗ ЗАВИСИМОСТЕЙ
    $pathsWithDependencies = $Results | Where-Object { $_.Dependencies.Count -gt 0 }
    if ($pathsWithDependencies.Count -gt 0) {
        [void]$stringBuilder.AppendLine("АНАЛИЗ ЗАВИСИМОСТЕЙ:")
        [void]$stringBuilder.AppendLine("-" * 40)
        [void]$stringBuilder.AppendLine("Найдено путей с зависимостями: $($pathsWithDependencies.Count)")
        
        $allDependencies = $Results | ForEach-Object { $_.Dependencies } | Where-Object { $_ } | Sort-Object | Get-Unique
        if ($allDependencies.Count -gt 0) {
            [void]$stringBuilder.AppendLine("Затронутые программы:")
            foreach ($dep in $allDependencies) {
                [void]$stringBuilder.AppendLine("  - $dep")
            }
        }
        [void]$stringBuilder.AppendLine()
    }
    
    # ДЕТАЛЬНЫЙ АНАЛИЗ РАЗДЕЛОВ ПО УРОВНЯМ БЕЗОПАСНОСТИ
    [void]$stringBuilder.AppendLine("ДЕТАЛЬНЫЙ АНАЛИЗ РАЗДЕЛОВ:")
    [void]$stringBuilder.AppendLine("=" * 80)
    
    # Группируем по уровням безопасности для удобного отображения
    foreach ($safetyLevel in @("Critical", "Dangerous", "Caution", "Unknown", "Safe")) {
        $levelResults = $Results | Where-Object { $_.SafetyLevel -eq $safetyLevel }
        if ($levelResults.Count -eq 0) { continue }
        
        [void]$stringBuilder.AppendLine()
        [void]$stringBuilder.AppendLine("$safetyLevel ($($levelResults.Count) записей):")
        [void]$stringBuilder.AppendLine("-" * 60)
        
        foreach ($result in $levelResults) {
            [void]$stringBuilder.AppendLine("ПУТЬ: $($result.Path)")
            [void]$stringBuilder.AppendLine("Уровень безопасности: $($result.SafetyLevel)")
            [void]$stringBuilder.AppendLine("Описание: $($result.Description)")
            [void]$stringBuilder.AppendLine("Рекомендация: $($result.RecommendedAction)")
            [void]$stringBuilder.AppendLine("Оценка важности: $($result.ImportanceScore) баллов")
            
            # Зависимости
            if ($result.Dependencies.Count -gt 0) {
                [void]$stringBuilder.AppendLine("Зависимости: $($result.Dependencies -join ', ')")
            }
            
            # Детали ключа
            $keyDetails = Get-RegistryKeyDetails -RegistryPath $result.Path
            [void]$stringBuilder.AppendLine("Детали ключа:")
            [void]$stringBuilder.AppendLine("  - Подразделов: $($keyDetails.SubKeyCount)")
            [void]$stringBuilder.AppendLine("  - Значений: $($keyDetails.ValueCount)")
            [void]$stringBuilder.AppendLine("  - Время изменения: $($keyDetails.LastWriteTime)")
            if ($keyDetails.ContainsUserData) { [void]$stringBuilder.AppendLine("  - Содержит пользовательские данные") }
            if ($keyDetails.ContainsSettings) { [void]$stringBuilder.AppendLine("  - Содержит настройки") }
            if ($keyDetails.ContainsFileAssociations) { [void]$stringBuilder.AppendLine("  - Связано с файловыми ассоциациями") }
            if ($keyDetails.IsSystemKey) { [void]$stringBuilder.AppendLine("  - Системный ключ") }
            
            # Значения для этого раздела
           $sectionValues = $Values | Where-Object { $_.Path -eq $result.Path -and (
				$_.Name -match "[\\:]$AppName\.exe" -or 
				$_.Data -match "[\\:]$AppName\.exe" -or
				($_.Name -like "*FriendlyAppName*" -and $_.Data -like "*$AppName*") -or
				($_.Name -like "*ApplicationCompany*" -and $_.Data -like "*$AppName*")
				)
			}
            if ($sectionValues.Count -gt 0) {
                [void]$stringBuilder.AppendLine("Значения ($($sectionValues.Count)):")
                foreach ($value in $sectionValues) {
                    $valuePreview = if ($value.Data.Length -gt 100) { 
                        $value.Data.Substring(0, 100) + "..." 
                    } else { 
                        $value.Data 
                    }
                    [void]$stringBuilder.AppendLine("  - $($value.Name) [$($value.Type)] = $valuePreview")
                }
            }
            
            [void]$stringBuilder.AppendLine()
        }
    }
    
    # ПРИЛОЖЕНИЕ: ВСЕ ЗНАЧЕНИЯ РЕЕСТРА
    [void]$stringBuilder.AppendLine()
    [void]$stringBuilder.AppendLine("ПРИЛОЖЕНИЕ: ВСЕ ЗНАЧЕНИЯ РЕЕСТРА")
    [void]$stringBuilder.AppendLine("=" * 80)
    
    foreach ($value in $Values) {
        [void]$stringBuilder.AppendLine("[$($value.SafetyLevel)] $($value.Path)")
        [void]$stringBuilder.AppendLine("  $($value.Name) [$($value.Type)] = $($value.Data)")
        [void]$stringBuilder.AppendLine("  Описание: $($value.SafetyDescription)")
        [void]$stringBuilder.AppendLine()
    }
    
    # ИТОГОВЫЕ РЕКОМЕНДАЦИИ
    [void]$stringBuilder.AppendLine()
    [void]$stringBuilder.AppendLine("ИТОГОВЫЕ РЕКОМЕНДАЦИИ:")
    [void]$stringBuilder.AppendLine("=" * 80)
    [void]$stringBuilder.AppendLine("1. ПЕРЕД УДАЛЕНИЕМ СОЗДАЙТЕ ТОЧКУ ВОССТАНОВЛЕНИЯ СИСТЕМЫ")
    [void]$stringBuilder.AppendLine("2. Удаляйте только записи уровня 'Safe'")
    [void]$stringBuilder.AppendLine("3. Для записей 'Caution' проверьте зависимости")
    [void]$stringBuilder.AppendLine("4. Записи 'Dangerous' и 'Critical' не удаляйте без веской причины")
    [void]$stringBuilder.AppendLine("5. Создайте резервную копию реестра перед массовым удалением")
    [void]$stringBuilder.AppendLine()
    [void]$stringBuilder.AppendLine("Время выполнения скрипта: $((Get-Date) - $Global:ScriptStartTime)")
    
    # Сохраняем отчет
    try {
        $reportContent = $stringBuilder.ToString()
        $reportContent | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Host "Улучшенный отчет сохранен в: $OutputFile" -ForegroundColor Green
    }
    catch {
        Write-Error "Ошибка сохранения отчета: $($_.Exception.Message)"
        # Fallback - сохраняем простой отчет
        try {
            "Простой отчет для $AppName`nНайдено записей: $($Results.Count)" | Out-File -FilePath $OutputFile -Encoding UTF8
        }
        catch {
            Write-Error "Не удалось сохранить даже простой отчет"
        }
    }
}

# =============================================================================
# КОНФИГУРАЦИЯ И СИСТЕМНЫЕ ФУНКЦИИ
# =============================================================================

function Export-RegistrySearchConfig {
    param([string]$ConfigPath)
    
    try {
        $Script:Config | ConvertTo-Json -Depth 5 | Out-File -FilePath $ConfigPath -Encoding UTF8
        Write-Host "Конфигурация экспортирована в: $ConfigPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Ошибка экспорта конфигурации: $($_.Exception.Message)"
        return $false
    }
}

function Import-RegistrySearchConfig {
    param([string]$ConfigPath)
    
    if (Test-Path $ConfigPath) {
        try {
            $configContent = Get-Content $ConfigPath -Raw -ErrorAction Stop
            $loadedConfig = $configContent | ConvertFrom-Json -AsHashtable
            
            # Объединяем с конфигурацией по умолчанию
            foreach ($category in $loadedConfig.Keys) {
                foreach ($key in $loadedConfig[$category].Keys) {
                    $Script:Config[$category][$key] = $loadedConfig[$category][$key]
                }
            }
            
            Write-Host "Конфигурация загружена из: $ConfigPath" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "Ошибка загрузки конфигурации: $($_.Exception.Message)"
            return $false
        }
    }
    
    return $false
}

function Test-SystemIntegrity {
    # Проверка критических системных файлов перед удалением
    $criticalFiles = @(
        "$env:SystemRoot\System32\ntoskrnl.exe"
        "$env:SystemRoot\System32\winload.exe"
        "$env:SystemRoot\System32\hal.dll"
    )
    
    foreach ($file in $criticalFiles) {
        if (-not (Test-Path $file)) {
            Write-Warning "Обнаружена проблема целостности системы: $file"
            return $false
        }
    }
    return $true
}

# =============================================================================
# ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ АНАЛИЗА
# =============================================================================
function Get-KeyImportanceScore {
    param([string]$RegistryPath)
    
    $keyDetails = Get-RegistryKeyDetails -RegistryPath $RegistryPath
    return $keyDetails.ImportanceScore
}

# ====================================================================================================



# Инициализация
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Для полного доступа к реестру рекомендуется запустить скрипт от имени администратора"
}

$Global:ScriptStartTime = Get-Date

if (-not $OutputFile) {
    $OutputFile = "RegistrySearch_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
}

if (-not $RegExportFile) {
    $RegExportFile = "RegistryExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
}

$Logger = [RegistrySearchLogger]::new((Get-Location).Path)

if ($Script:Config.Logging.Debug) {
    $Logger.EnableDebug()
}

$Logger.LogInfo("Инициализация скрипта завершена")
$Logger.LogInfo("Приложение для поиска: $AppName")
$Logger.LogInfo("Файл вывода: $OutputFile")

try {
	# ОБНОВЛЕННАЯ ОСНОВНАЯ ЛОГИКА СКРИПТА
    $Logger.LogInfo("Запуск расширенного поиска записей реестра для: $AppName")
    $Logger.LogInfo("Время начала: $(Get-Date)")
    $Logger.LogInfo("Максимальная глубина поиска: $MaxDepth")
    $Logger.LogInfo("Режим поиска: $(if ($ExactMatch) { 'Точное соответствие' } else { 'Частичное соответствие' })")
    $Logger.LogInfo("Фильтрация ложных срабатываний: $(if ($FilterFalsePositives) { 'Включена' } else { 'Выключена' })")
	
	# ПРИМЕНЕНИЕ ИНТЕЛЛЕКТУАЛЬНЫХ ШАБЛОНОВ
    Apply-IntelligentSearch -AppName $AppName -SearchPattern ([ref]$AppName) -MaxDepth ([ref]$MaxDepth)
	
    # ПРОВЕРКА ЦЕЛОСТНОСТИ СИСТЕМЫ
    if (-not (Test-SystemIntegrity)) {
        $Logger.LogWarning("Обнаружены проблемы целостности системы. Рекомендуется проверить систему перед продолжением.")
    }

    # ВЫБОР МЕТОДА ПОИСКА (ПАРАЛЛЕЛЬНЫЙ ИЛИ ПОСЛЕДОВАТЕЛЬНЫЙ)
    $hives = Get-RegistryHives
	
    # Проверяем, что есть доступные разделы
    if ($hives.Count -eq 0) {
        $Logger.LogError("Нет доступных разделов реестра для поиска. Проверьте права доступа.")
        return
    }

    $Logger.LogInfo("Доступные разделы реестра: $($hives.Count)")

    # ОЧИСТКА КЭША ПЕРЕД НАЧАЛОМ ПОИСКА
    if ($Script:Config.Performance.CacheEnabled) {
        Clear-RegistryCache -CacheType "All"
    }

    # Выбор метода поиска
    switch ($ThreadingMode) {
        "MultiThread" {
            $Logger.LogInfo("Принудительный МНОГОПОТОЧНЫЙ режим для $($hives.Count) разделов...")
            $allResults = Search-RegistryAllHives -SearchPattern $AppName -MaxDepth $MaxDepth -ExactMatch $ExactMatch -IncludeStandardPaths $IncludeStandardPaths -UseMultiThreading $true
        }
        "SingleThread" {
            $Logger.LogInfo("Принудительный ОДНОПОТОЧНЫЙ режим...")
            $allResults = Search-RegistryAllHives -SearchPattern $AppName -MaxDepth $MaxDepth -ExactMatch $ExactMatch -IncludeStandardPaths $IncludeStandardPaths -UseMultiThreading $false
        }
        default { # Auto
            if ($hives.Count -ge $Config.Search.AutoThreadingThreshold -and $MaxDepth -le 8) {
                $Logger.LogInfo("Автоматический выбор: МНОГОПОТОЧНЫЙ поиск для $($hives.Count) разделов...")
                $allResults = Search-RegistryAllHives -SearchPattern $AppName -MaxDepth $MaxDepth -ExactMatch $ExactMatch -IncludeStandardPaths $IncludeStandardPaths -UseMultiThreading $true
            } else {
                $Logger.LogInfo("Автоматический выбор: ОДНОПОТОЧНЫЙ поиск...")
                $allResults = Search-RegistryAllHives -SearchPattern $AppName -MaxDepth $MaxDepth -ExactMatch $ExactMatch -IncludeStandardPaths $IncludeStandardPaths -UseMultiThreading $false
            }
        }
    }

	# Удаляем дубликаты
	$allResults = $allResults | Sort-Object | Get-Unique

	# Применяем фильтрацию ложных срабатываний если включена
	if ($FilterFalsePositives) {
		$filteredResults = @()
		$filteredValues = [System.Collections.ArrayList]@()
		
		foreach ($result in $allResults) {
			$values = Get-RegistryValues -Path $result
			$hasValidValues = $false
			$pathValidValues = @()
			
			foreach ($value in $values) {
				# ПРОВЕРЯЕМ КАЖДОЕ ЗНАЧЕНИЕ ОТДЕЛЬНО
				if (-not (Test-IsFalsePositive -RegistryPath $result -ValueName $value.Name -ValueData $value.Data -SearchPattern $AppName)) {
					$hasValidValues = $true
					# Добавляем безопасность к значению
					$safetyLevel = Get-RegistrySafetyLevel -RegistryPath $result
					$value | Add-Member -NotePropertyName "SafetyLevel" -NotePropertyValue $safetyLevel -Force
					$value | Add-Member -NotePropertyName "SafetyDescription" -NotePropertyValue (Get-EnhancedSafetyDescription -SafetyLevel $safetyLevel -RegistryPath $result) -Force
					[void]$filteredValues.Add($value)
					$pathValidValues += $value
				}
			}
			
			if ($hasValidValues) {
				$filteredResults += $result
				Write-Host "  Сохранен путь: $result" -ForegroundColor Green
				Write-Host "    Valid values: $($pathValidValues.Count)" -ForegroundColor Gray
			} else {
				Write-Host "  Отфильтрован путь: $result" -ForegroundColor Yellow
			}
		}
		
		$allResults = $filteredResults
		# Сохраняем отфильтрованные значения для отчета
		$allValues = $filteredValues
		Write-Host "После фильтрации осталось: $($allResults.Count) путей и $($allValues.Count) значений" -ForegroundColor Yellow
	}

	# Классифицируем найденные пути по уровню опасности С УЛУЧШЕННОЙ КЛАССИФИКАЦИЕЙ
	$classifiedResults = @()
	$progress = 0

	Write-Host "Анализ безопасности и зависимостей..." -ForegroundColor Cyan
	foreach ($result in $allResults) {
		$progress++
		$percentComplete = [math]::Round(($progress / $allResults.Count) * 100, 1)
		
		Write-Progress -Activity "Анализ безопасности" `
					   -Status "Классификация записей $progress из $($allResults.Count) - $percentComplete%" `
					   -PercentComplete $percentComplete
		
		# ИСПОЛЬЗУЕМ УЛУЧШЕННУЮ КЛАССИФИКАЦИЮ
		$safetyLevel = Get-RegistrySafetyLevel -RegistryPath $result
		$classifiedResults += [PSCustomObject]@{
			Path = $result
			SafetyLevel = $safetyLevel
			Description = Get-EnhancedSafetyDescription -SafetyLevel $safetyLevel -RegistryPath $result
			# ДОБАВЛЯЕМ АНАЛИЗ ЗАВИСИМОСТЕЙ ДЛЯ ОПАСНЫХ ПУТЕЙ
			Dependencies = if ($safetyLevel -eq "Caution" -or $safetyLevel -eq "Dangerous" -or $safetyLevel -eq "Unknown") { 
				(Get-RegistryDependencies -RegistryPath $result).Programs
			} else { @() }
			ImportanceScore = Get-KeyImportanceScore -RegistryPath $result
			RecommendedAction = Get-RecommendedAction -RegistryPath $result
		}
	}

	Write-Progress -Activity "Анализ безопасности" -Completed

	# Группируем по уровням безопасности
	$groupedResults = $classifiedResults | Group-Object SafetyLevel

	Write-Host "`nОбщий результат:" -ForegroundColor Green
	Write-Host "Найдено разделов реестра: $($allResults.Count)" -ForegroundColor White

	# Вывод статистики по уровням безопасности
	Write-Host "`nКЛАССИФИКАЦИЯ ПО УРОВНЮ БЕЗОПАСНОСТИ:" -ForegroundColor Cyan
	foreach ($group in $groupedResults | Sort-Object Name) {
		$color = Get-SafetyLevelColor -SafetyLevel $group.Name
		Write-Host "  $($group.Name): $($group.Count) записей" -ForegroundColor $color
		Write-Host "    $($group.Group[0].Description)" -ForegroundColor Gray
	}

	if ($allResults.Count -gt 0) {
		
#		Write-Host "`nСбор информации о значениях..." -ForegroundColor Cyan
#		$progress = 0
#		$allValues = [System.Collections.ArrayList]@()
#
#		foreach ($result in $allResults) {
#			$progress++
#			$percentComplete = [math]::Round(($progress / $allResults.Count) * 100, 1)
#			
#			Write-Progress -Activity "Сбор значений реестра" `
#						   -Status "Обработка $progress из $($allResults.Count) - $percentComplete%" `
#						   -PercentComplete $percentComplete `
#						   -CurrentOperation "Путь: $(if ($result.Length -gt 50) { $result.Substring(0, 50) + '...' } else { $result })"
#			
#			$values = Get-RegistryValues -Path $result
#			foreach ($value in $values) {
#				# ИСПОЛЬЗУЕМ УЛУЧШЕННУЮ КЛАССИФИКАЦИЮ
#				$safetyLevel = Get-RegistrySafetyLevel -RegistryPath $result
#				$value | Add-Member -NotePropertyName "SafetyLevel" -NotePropertyValue $safetyLevel
#				$value | Add-Member -NotePropertyName "SafetyDescription" -NotePropertyValue (Get-EnhancedSafetyDescription -SafetyLevel $safetyLevel -RegistryPath $result)
#				[void]$allValues.Add($value)
#			}
#		}

		Write-Progress -Activity "Сбор значений реестра" -Completed
		Write-Host "Сбор значений завершен. Найдено: $($allValues.Count) значений" -ForegroundColor Green

		# Экспорт реестра если запрошен
		if ($ExportReg) {
			Export-RegistryKeys -RegistryPaths $allResults -ExportFile $RegExportFile
		}

		# СОЗДАЕМ УЛУЧШЕННЫЙ ОТЧЕТ С ПОМОЩЬЮ НОВОЙ ФУНКЦИИ
		New-EnhancedReport -Results $classifiedResults -Values $allValues -OutputFile $OutputFile -AppName $AppName -MaxDepth $MaxDepth

		# Вывод краткой информации в консоль с цветами
		Write-Host "`nКраткие результаты по уровням безопасности:" -ForegroundColor Cyan
		
		foreach ($group in $groupedResults | Sort-Object Name) {
			$color = Get-SafetyLevelColor -SafetyLevel $group.Name
			Write-Host "`n$($group.Name) ($($group.Count)):" -ForegroundColor $color
			Write-Host "$($group.Group[0].Description)" -ForegroundColor Gray
			
			# Показываем по 3 примера для каждого уровня
			$examples = $group.Group | Select-Object -First 3
			foreach ($example in $examples) {
				Write-Host "  $($example.Path)" -ForegroundColor Gray 
				# ПОКАЗЫВАЕМ ЗАВИСИМОСТИ ДЛЯ ОПАСНЫХ ПУТЕЙ
				if ($example.Dependencies.Count -gt 0) {
					Write-Host "    Зависимости: $($example.Dependencies -join ', ')" -ForegroundColor DarkYellow
				}
				# ПОКАЗЫВАЕМ РЕКОМЕНДАЦИИ ДЛЯ НЕИЗВЕСТНЫХ ПУТЕЙ
				if ($example.SafetyLevel -eq "Unknown") {
					Write-Host "    Рекомендация: $($example.RecommendedAction)" -ForegroundColor Magenta
				}
			}
			if ($group.Count -gt 3) {
				Write-Host "  ... и еще $($group.Count - 3) записей" -ForegroundColor DarkGray
			}
		}
		
		# Рекомендации по удалению С УЧЕТОМ ЗАВИСИМОСТЕЙ
		Write-Host "`nРЕКОМЕНДАЦИИ ПО УДАЛЕНИЮ:" -ForegroundColor Yellow
		Write-Host "✓ БЕЗОПАСНО: Можно удалять все записи" -ForegroundColor Green
		Write-Host "⚠ ОСТОРОЖНО: Проверьте зависимости перед удалением" -ForegroundColor Yellow  
		Write-Host "✗ ОПАСНО: Не рекомендуется удалять (затрагивает другие программы)" -ForegroundColor Red
		Write-Host "☠ КРИТИЧЕСКИ: Никогда не удалять! (системные ключи)" -ForegroundColor DarkRed
		Write-Host "? НЕИЗВЕСТНО: Требуется ручная проверка зависимостей" -ForegroundColor Gray
		
		# ДОПОЛНИТЕЛЬНАЯ СТАТИСТИКА
		$totalDependencies = ($classifiedResults | Where-Object { $_.Dependencies.Count -gt 0 }).Count
		if ($totalDependencies -gt 0) {
			Write-Host "`nСТАТИСТИКА ЗАВИСИМОСТЕЙ:" -ForegroundColor Cyan
			Write-Host "Путей с зависимостями: $totalDependencies" -ForegroundColor White
			
			$allDependencies = $classifiedResults | ForEach-Object { $_.Dependencies } | Where-Object { $_ } | Sort-Object | Get-Unique
			if ($allDependencies.Count -gt 0) {
				Write-Host "Затронутые программы:" -ForegroundColor Gray
				foreach ($dep in $allDependencies | Select-Object -First 10) {
					Write-Host "  - $dep" -ForegroundColor Gray
				}
				if ($allDependencies.Count -gt 10) {
					Write-Host "  ... и еще $($allDependencies.Count - 10) программ" -ForegroundColor DarkGray
				}
			}
		}
		
	} else {
		Write-Host "Записей реестра для приложения '$AppName' не найдено." -ForegroundColor Red
	}

    # Добавляйте вызовы логгера в критические места:
    $Logger.LogInfo("Поиск завершен. Найдено записей: $($allResults.Count)")
    $Logger.LogSuccess("Отчет сохранен в: $OutputFile")
    
}
catch [System.Management.Automation.ParameterBindingException] {
    $Logger.LogError("Ошибка привязки параметров: $($_.Exception.Message)")
    $Logger.LogInfo("Проверьте правильность параметров запуска")
}
catch [System.ArgumentException] {
    $Logger.LogError("Ошибка аргументов: $($_.Exception.Message)")
    $Logger.LogInfo("Проверьте переданные параметры")
}
catch [System.UnauthorizedAccessException] {
    $Logger.LogError("Ошибка доступа: $($_.Exception.Message)")
    $Logger.LogError("Запустите скрипт от имени администратора")
}
catch [System.OutOfMemoryException] {
    $Logger.LogError("Недостаточно памяти для обработки результатов")
    $Logger.LogWarning("Уменьшите MaxDepth или используйте более строгую фильтрацию")
    Clear-RegistryCache -CacheType "All"
}
catch {
    $Logger.LogError("Критическая ошибка выполнения скрипта: $($_.Exception.Message)")
    $Logger.LogError("Стек вызовов: $($_.ScriptStackTrace)")
}
finally {
    $executionTime = (Get-Date) - $Global:ScriptStartTime
    $Logger.LogInfo("Поиск завершен в: $(Get-Date)")
    $Logger.LogInfo("Общее время выполнения: $executionTime")
    $Logger.LogInfo("Путь к файлу лога: $($Logger.GetLogPath())")
    
    # ФИНАЛЬНАЯ ОЧИСТКА ПАМЯТИ
    Clear-RegistryCache -CacheType "All"
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
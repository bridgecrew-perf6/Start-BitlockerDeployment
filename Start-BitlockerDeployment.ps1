<#
    .SYNOPSIS
    .DESCRIPTION
    .PARAMETER Confirm
        [Int] Determine what type of changes should be prompted before executing.
            0 - Confirm both environment and object changes.
            1 - Confirm only object changes. (Default)
            2 - Confirm nothing!
            Object Changes are changes that are permanent such as file modifications, registry changes, etc.
            Environment changes are changes that can normally be restored via restart, such as opening/closing applications.
            Note: This configuration will take priority over Debugger settings for confirm action preference.
    .PARAMETER Debugger
        [Int] Used primarily to quickly apply multiple arguments making script development and debugging easier. Useful only for developers.
            1. Incredibly detailed play-by-play execution of the script. Equivilent to '-Change 0',  '-LogLevel Verbose', script wide 'ErrorAction Stop', 'Set-StrictMode -latest', and lastly 'Set-PSDebug -Trace 1'
            2. Equivilent to '-Change 0', '-LogLevel Verbose', and script wide 'ErrorAction Stop'.
            3. Equivilent to '-Change 1', '-LogLevel Info', and enables verbose on PS commands.
    .PARAMETER LogLevel
        [String] Used to display log output with definitive degrees of verboseness.
            Verbose = Display everything the script is doing with extra verbose messages, helpful for debugging, useless for everything else.
            Debug   = Display all messages at a debug or higher level, useful for debugging.
            Info    = Display all informational messages and higher. (Default)
            Warn    = Display only warning and error messages.
            Error   = Display only error messages.
            None    = Display absolutely nothing.
    .INPUTS
        None
    .OUTPUTS
        None
    .NOTES
    VERSION     DATE			NAME						DESCRIPTION
    ___________________________________________________________________________________________________________
    1.0         28 Sept 2020	Warilia, Nicholas R.		Initial version
    Script tested on the following Powershell Versions
        1.0   2.0   3.0   4.0   5.0   5.1
    ----- ----- ----- ----- ----- -----
        X    X      X     X     âœ“    âœ“
    Credits:
        (1) Script Template: https://gist.github.com/9to5IT/9620683
    To Do List:
        (1) Get Powershell Path based on version (stock powershell, core, etc.)
    Additional Information:
        #About '#Requires': https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_requires?view=powershell-5.1
        Show-Command Creates GUI window with all parameter; super easy to see what options are available for a command.
        Get-Verb Shows all approved powershell versb
#>

[CmdletBinding(
    ConfirmImpact='None',
    DefaultParameterSetName='Site',
    HelpURI="",
    SupportsPaging=$False,
    SupportsShouldProcess=$True,
    PositionalBinding=$True
)] Param (
    [string]$test,
    [ValidateSet(0,1,2)]
    [Int]$Confim = 1,
    [ValidateSet(0,1,2)]
    [Int]$Debugger = 3,
    [ValidateSet('Verbose','Debug','Info','Warn','Error','Fatal','Off')]
    [String]$LogLevel = 'Info',
    [ValidateSet('Log','Host','LogHost','Auto')]
    [String]$LogOutput='Auto',
    [Switch]$Testing
)

#region --------------------------------------------- [Manual Configuration] ----------------------------------------------------
    #Require Admin Privilages.
    New-Variable -Force -Name ScriptConfig -value @{
        #Should script enforce running as admin.
        RequireAdmin = $False
    }

#endregion,#')}]#")}]#'")}]

#region ----------------------------------------------- [Required Functions] -----------------------------------------------------

    Function Write-nLog {
        <#
            .SYNOPSIS
                Standardized & Easy to use logging function.
            .DESCRIPTION
                Easy and highly functional logging function that can be dropped into any script to add logging capability without hindering script performance.
            .PARAMETER type
                Set the event level of the log event.
                [Options]
                    Info, Warning, Error, Debug
            .PARAMETER message
                Set the message text for the event.
            .PARAMETER ErrorCode
                Set the Error code for Error & fatal level events. The error code will be displayed in front of the message text for the event.
            .PARAMETER WriteHost
                Force writing to host reguardless of SetWriteLog setting for this specific instance.
            .PARAMETER WriteLog
                Force writing to log reguardless of SetWriteLog setting for this specific instance.
            .PARAMETER SetLogLevel
                Set the log level for the nLog function for all future calls. When setting a log level all logs at
                the defined level will be logged. If you set the log level to warning (default) warning messages
                and all events above that such as error and fatal will also be logged.
                (1) Debug: Used to document events & actions within the script at a very detailed level. This level
                is normally used during script debugging or development and is rarely set once a script is put into
                production
                (2) Information: Used to document normal application behavior and milestones that may be useful to
                keep track of such. (Ex. File(s) have been created/removed, script completed successfully, etc)
                (3) Warning: Used to document events that should be reviewed or might indicate there is possibly
                unwanted behavior occuring.
                (4) Error: Used to document non-fatal errors indicating something within the script has failed.
                (5) Fatal: Used to document errors significant enough that the script cannot continue. When fatal
                errors are called with this function the script will terminate.
                [Options]
                    1,2,3,4,5
            .PARAMETER SetLogFile
                Set the fully quallified path to the log file you want used. If not defined, the log will use the
                "$Env:SystemDrive\ProgramData\Scripts\Logs" directory and will name the log file the same as the
                script name.
            .PARAMETER SetWriteHost
                Configure if the script should write events to the screen. (Default: $False)
                [Options]
                    $True,$False
            .PARAMETER SetWriteLog
                Configure if the script should write events to the screen. (Default: $True)
                [Options]
                    $True,$False
            .PARAMETER Close
                Removes all script-level variables set while nLog creates while running.
            .INPUTS
                None
            .OUTPUTS
                None
            .NOTES
            VERSION     DATE			NAME						DESCRIPTION
            ___________________________________________________________________________________________________________
            1.0			25 May 2020		Warila, Nicholas R.			Initial version
            2.0			28 Aug 2020		Warila, Nicholas R.			Complete rewrite of major portions of the script, significant improvement in script performance (about 48%), and updated log format.
            Credits:
                (1) Script Template: https://gist.github.com/9to5IT/9620683
        #>
        Param (
            [Parameter(Mandatory=$True,Position=0)]
            [ValidateSet('Debug','Info','Warning','Error','Fatal')]
            [String]$Type,
            [Parameter(Mandatory=$True,ValueFromPipeline=$False,Position=1)]
            [String]$Message,
            [Parameter(Mandatory=$False,ValueFromPipeline=$False,Position=2)][ValidateRange(0,9999)]
            [Int]$ErrorCode = 0,
            [Switch]$WriteHost,
            [Switch]$WriteLog,
            [Switch]$Initialize,
            [Parameter(Mandatory=$False,ValueFromPipeline=$False)]
            [ValidateSet('Debug','Info','Warning','Error','Fatal')]
            [String]$SetLogLevel,
            [Parameter(Mandatory=$False,ValueFromPipeline=$False)]
            [String]$SetLogFile,
            [Parameter(Mandatory=$False,ValueFromPipeline=$False)]
            [String]$SetLogDir,
            [Parameter(Mandatory=$False,ValueFromPipeline=$False)]
            [Bool]$SetWriteHost,
            [Parameter(Mandatory=$False,ValueFromPipeline=$False)]
            [Bool]$SetWriteLog,
            [Parameter(Mandatory=$False,ValueFromPipeline=$False)]
            [ValidateSet('Local','UTC')]
            [String]$SetTimeLocalization,
            [ValidateSet('nLog','CMTrace')]
            [String]$SetLogFormat,
            [Int]$Line,
            [Switch]$Close
        )

        #Best practices to ensure function works exactly as expected, and prevents adding "-ErrorAction Stop" to so many critical items.
        #$Local:ErrorActionPreference = 'Stop'
        #Set-StrictMode -Version Latest

        #Allows us to turn on verbose on all powershell commands when adding -verbose
        IF ($PSBoundParameters.ContainsKey('Verbose')) {
            Set-Variable -Name Verbose -Value $True
        } Else {
            IF (Test-Path -Path Variable:\verbose) {
                Set-Variable -Name Verbose -Value ([Bool]$Script:Verbose)
            } Else {
                Set-Variable -Name Verbose -Value $False
            }
        }

        New-Variable -Name StartTime -Value ([DateTime]::Now) -Force -Verbose:$Verbose -Description "Used to calculate timestamp differences between log calls."

        #Ensure all the required script-level variables are set.
        IF ((-Not (Test-Path variable:Script:nLogInitialize)) -OR $Initialize) {
            New-Variable -Name SetTimeLocalization -Verbose:$Verbose -Scope Script -Force -Value ([DateTime]::Now)
            New-Variable -Name nLogFormat          -Verbose:$Verbose -Scope Script -Force -Value "nLog"
            New-Variable -Name nLogLevel           -Verbose:$Verbose -Scope Script -Force -Value ([String]"Info")
            New-Variable -Name nLogInitialize      -Verbose:$Verbose -Scope Script -Force -Value $True
            New-Variable -Name nLogWriteHost       -Verbose:$Verbose -Scope Script -Force -Value $False
            New-Variable -Name nLogWriteLog        -Verbose:$Verbose -Scope Script -Force -Value $True
            New-Variable -Name nLogLastTimeStamp   -Verbose:$Verbose -Scope Script -Force -Value $StartTime

            New-Variable -Name nLogDir             -Verbose:$Verbose -Scope Script -Force -Value $ScriptEnv.Script.DirectoryName
            New-Variable -Name nLogFile            -Verbose:$Verbose -Scope Script -Force -Value "$($ScriptEnv.Script.BaseName)`.log"
            New-Variable -Name nLogFullName        -Verbose:$Verbose -Scope Script -Force -Value "$nLogDir\$nLogFile"
            New-Variable -Name nLogFileValid       -Verbose:$Verbose -Scope Script -Force -Value $False

            New-Variable -Name nLogLevels        -Verbose:$Verbose -Scope Script -Force -Value $([HashTable]@{
                Debug   = @{ Text = "[DEBUG]  "; LogLevel = [Int]'1'; tForeGroundColor = "Cyan";   }
                Info    = @{ Text = "[INFO]   "; LogLevel = [Int]'2'; tForeGroundColor = "White";  }
                Warning = @{ Text = "[WARNING]"; LogLevel = [Int]'3'; tForeGroundColor = "DarkRed";}
                Error   = @{ Text = "[ERROR]  "; LogLevel = [Int]'4'; tForeGroundColor = "Red";    }
                Fatal   = @{ Text = "[FATAL]  "; LogLevel = [Int]'5'; tForeGroundColor = "Red";    }
            })
        }

        Switch($PSBoundParameters.Keys) {
            'SetLogLevel'  {Set-Variable -Name nLogLevel     -Verbose:$Verbose -Scope Script -Force -Value $SetLogLevel  }
            'SetLogFormat' {Set-Variable -Name nLogFormat    -Verbose:$Verbose -Scope Script -Force -Value $SetLogFormat}
            'SetWriteHost' {Set-Variable -Name nLogWriteHost -Verbose:$Verbose -Scope Script -Force -Value $SetWriteHost }
            'SetWriteLog'  {Set-Variable -Name nLogWriteLog  -Verbose:$Verbose -Scope Script -Force -Value $SetWriteLog  }
            'SetLogDir'    {
                Set-Variable -Name nLogDir       -Verbose:$Verbose -Scope Script -Force -Value $SetLogDir
                Set-Variable -Name nLogFileValid -Verbose:$Verbose -Scope Script -Force -Value $False
            }
            'SetLogFile'   {
                Set-Variable -Name nLogFile      -Verbose:$Verbose -Scope Script -Force -Value "$($SetLogFile -replace "[$([string]::join('',([System.IO.Path]::GetInvalidFileNameChars())) -replace '\\','\\')]",'_')"
                Set-Variable -Name nLogFileValid -Verbose:$Verbose -Scope Script -Force -Value $False
            }
            'SetTimeLocalization' {
                #Prevent issues where timestamp will show huge differences in time between code calls when converting UCT and Local
                If ($Script:nLogTimeLocalization -ne $SetTimeLocalization -AND -NOT [String]::IsNullOrWhiteSpace($Script:nLogLastTimeStamp)) {
                    If ($Script:nLogTimeLocalization -eq 'Local') {
                        Set-Variable -Name nLogLastTimeStamp -Verbose:$Verbose -Scope Script -Force -Value $nLogLastTimeStamp.ToLocalTime()
                    } Else {
                        Set-Variable -Name nLogLastTimeStamp -Verbose:$Verbose -Scope Script -Force -Value $nLogLastTimeStamp.ToUniversalTime()
                    }
                }
                Set-Variable -Name nLogTimeLocalization -Verbose:$Verbose -Scope Script -Force -Value $SetTimeLocalization
            }
        }

        IF (-NOT $PSBoundParameters.ContainsKey('Line')) {
            Set-Variable Line -Verbose:$Verbose -Force -Value $MyInvocation.ScriptLineNumber
        }
        IF ($PSBoundParameters.ContainsKey('WriteHost')) { $tWriteHost = $True } Else { $tWriteHost = $Script:nLogWriteHost }
        IF ($PSBoundParameters.ContainsKey('WriteLog'))  { $tWriteLog  = $True } Else { $tWriteLog  = $Script:nLogWriteLog  }

        #Determine if script log level greater than or equal to current log event level and we actually are configured to write something.
        IF ($Script:nLogLevels[$Type]["LogLevel"] -ge $Script:nLogLevels[$Script:nLogLevel]["LogLevel"] -AND $Script:nLogLevel -ne 0 -AND ($tWriteHost -EQ $True -OR $tWriteLog -EQ $True)) {

            #Convert TimeStamp if needed
            IF ($Script:nLogTimeLocalization -eq 'UTC') {
                Set-Variable -Name StartTime -Value ($StartTime.ToUniversalTime().ToString("s",[System.Globalization.CultureInfo]::InvariantCulture))
            }

            #Code Block if writing out to log file.
            If ($tWriteLog) {
                IF ($Script:nLogFileValid -eq $False) {
                    Set-Variable -Name nLogFullName      -Verbose:$Verbose -Scope Script -Force -Value (Join-Path -Path $Script:nLogDir -ChildPath $Script:nLogFile)

                    #[Test Write access to results file.]
                    If ([system.io.file]::Exists($Script:nLogFullName)) {
                        Try {
                            (New-Object -TypeName 'System.IO.FileStream' -ArgumentList $Script:nLogFullName,([System.IO.FileMode]::Open),([System.IO.FileAccess]::Write),([System.IO.FileShare]::Write),4096,([System.IO.FileOptions]::None)).Close()
                        } Catch {
                            Write-Error -Message "Unable to open $Script:nLogFile. (Full Path: '$Script:nLogFullName')"
                            exit
                        }
                    } Else {
                        Try {
                            (New-Object -TypeName 'System.IO.FileStream' -ArgumentList $Script:nLogFullName,([System.IO.FileMode]::Create),([System.IO.FileAccess]::ReadWrite),([System.IO.FileShare]::ReadWrite),4096,([System.IO.FileOptions]::DeleteOnClose)).Close()
                        } Catch {
                            Write-Error -Message "Unable to create $Script:nLogFile. (Full Path: '$Script:nLogFullName')"
                        }
                    }
                    Set-Variable -Name nLogFileValid -Verbose:$Verbose -Scope Script -Force -Value $True
                }

                New-Variable -Force -Verbose:$Verbose -Name FileStream   -Value (New-Object -TypeName 'System.IO.FileStream' -ArgumentList $Script:nLogFullName,([System.IO.FileMode]::Append),([System.IO.FileAccess]::Write),([System.IO.FileShare]::Write),4096,([System.IO.FileOptions]::WriteThrough))
                New-Variable -Force -Verbose:$Verbose -Name StreamWriter -Value (New-Object -TypeName 'System.IO.StreamWriter' -ArgumentList $FileStream,([Text.Encoding]::Default),4096,$False)

                Switch ($Script:nLogFormat) {
                    'CMTrace'    {
                        [String]$WriteLine = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">' -f `
                        $Message,
                        ([DateTime]$StartTime).ToString('HH:mm:ss.fff+000'),
                        ([DateTime]$StartTime).ToString('MM-dd-yyyy'),
                        "$($ScriptEnv.Script.Name):$($Line)",
                        "1"
                    }
                    'nLog' {
                        $WriteLine = "$StartTime||$Env:COMPUTERNAME||$Type||$($ErrorCode.ToString(`"0000`"))||$Line)||$Message"
                    }
                }
                $StreamWriter.WriteLine($WriteLine)
                $StreamWriter.Close()
            }

            #Code Block if writing out to log host.
            IF ($tWriteHost) {
                Write-Host -ForegroundColor $Script:nLogLevels[$Type]["tForeGroundColor"] -Verbose:$Verbose "$StartTime ($(((New-TimeSpan -Start $Script:nLogLastTimeStamp -End $StartTime -Verbose:$Verbose).Seconds).ToString('0000'))s) $($Script:nLogLevels[$Type]['Text']) [$($ErrorCode.ToString('0000'))] [Line: $($Line.ToString('0000'))] $Message"
            }

            #Ensure we have the timestamp of the last log execution.
            Set-Variable -Name nLogLastTimeStamp -Scope Script -Value $StartTime -Force -Verbose:$Verbose
        }

        #Remove Function Level Variables. This isn't needed unless manually running portions of the code instead of calling it via a funtion.
        #Remove-Variable -Name @("Message","SetLogLevel","SetLogFile","Close","SetWriteLog","SetWriteHost","LineNumber","ErrorCode","tWriteHost","WriteHost","tWriteLog","WriteLog","StartTime") -ErrorAction SilentlyContinue

        IF ($PSBoundParameters.ContainsKey('Close') -or $Type -eq 'Fatal') {
            Remove-Variable -Name @("nLogLastTimeStamp","nLogFileValid","nLogFile","nLogDir","nLogWriteLog","nLogWriteHost","nLogInitialize","nLogLastTimeStamp","nLogLevels","nLogFullName","nLogLevel") -Scope Script -ErrorAction SilentlyContinue
        }

        #Allow us to exit the script from the logging function.
        If ($Type -eq 'Fatal') {
            Exit
        }
    }

    Function Set-RegistryKey {
        <#
            .SYNOPSIS
                Used to set registry key value.

            .DESCRIPTION
                Robust function used to set a registry value with error handling and logging.

            .PARAMETER RegistryHive
                [String] Used to determine the default state of the ribbon in explorer when tablet mode is off.
                    HKEY_USERS            =
                    HKEY_CLASSES_ROOT     =
                    HKEY_CURRENT_CONFIG   =
                    HKEY_CURRENT_USER     =
                    HKEY_LOCAL_MACHINE    =

            .PARAMETER DataType
                [String] Used to determine the default state of the ribbon in explorer when tablet mode is on.
                    REG_BINARY    = Raw binary data. Most hardware component information is stored as binary data and is displayed in Registry Editor in hexadecimal format.
                    REG_DWORD     = Data represented by a number that is 4 bytes long (a 32-bit integer). Many parameters for device drivers and services are this type and are displayed in Registry Editor in binary, hexadecimal, or decimal format. Related values are DWORD_LITTLE_ENDIAN (least significant byte is at the lowest address) and REG_DWORD_BIG_ENDIAN (least significant byte is at the highest address).
                    REG_EXPAND_SZ = A variable-length data string. This data type includes variables that are resolved when a program or service uses the data.
                    REG_MULTI_SZ  = A multiple string. Values that contain lists or multiple values in a form that people can read are generally this type. Entries are separated by spaces, commas, or other marks.
                    REG_SZ        = A fixed-length text string.
                    REG_QWORD	  = Data represented by a number that is a 64-bit integer. This data is displayed in Registry Editor as a Binary Value and was introduced in Windows 2000.
                    REG_NONE      = Data without any particular type. This data is written to the registry by the system or applications and is displayed in Registry Editor in hexadecimal format as a Binary Value

            .PARAMETER CreateKey
                [Bool] Create the registry key if the key does not exist. This does not affect key properties/values, this only affects if the key containing the value should be created if it does not already exists.
                    True  = Create the key if the key does not already exists. (Default)
                    False = Do not create the key if it does not exist.

            .PARAMETER FixDataType
                [Bool] Determines if the script will update the DataType in the regsitry if the current item property doesn't match what the script thinks it should be.
                    True  = Remove and recreate item property if it doesn't match what the script thinks it should be.
                    False = Leave the item properties data type the same and just update the value. (Default)

            .PARAMETER Confirm
                [Int] Determine what type of changes should be prompted before executing.
                    0 - Confirm both environment and object changes.
                    1 - Confirm only object changes.
                    2 - Confirm nothing! (Default)
                    Object Changes are changes that are permanent such as file modifications, registry changes, etc.
                    Environment changes are changes that can normally be restored via restart, such as opening/closing applications.

            .INPUTS
                None

            .OUTPUTS
                None

            .NOTES
            VERSION     DATE			NAME						DESCRIPTION
            ___________________________________________________________________________________________________________
            1.0         01 April 2021	Warilia, Nicholas R.		Initial version


            Script tested on the following Powershell Versions
                1.0   2.0   3.0   4.0   5.0   5.1
            ----- ----- ----- ----- ----- -----
                X    X      X     X     ✓    ✓

            Credits:
                (1) Script Template: https://gist.github.com/9to5IT/9620683

            To Do List:
                (1) Get Powershell Path based on version (stock powershell, core, etc.)
        #>

        Param (
            [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [String]$Path,

            [Parameter(Mandatory=$False)]
            [ValidateSet('Binary','DWord','ExpandString','MultiString','String','QWord','None')]
            [String]$DataType,

            [Parameter(Mandatory=$False)]
            [ValidateNotNullOrEmpty()]
            [String]$Name,

            [Parameter(Mandatory=$False)]
            [ValidateNotNullOrEmpty()]
            [String]$Value,

            [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("HKEY_USERS","HKEY_CLASSES_ROOT","HKEY_CURRENT_CONFIG","HKEY_CURRENT_USER","HKEY_LOCAL_MACHINE")]
                [String]$RegistryHive,
            [Bool]$CreateKey = $True,
            [ValidateSet(0,1,2)]
            [Int]$Confim = 2,
            [Switch]$FixDataType,
            $Confirm = [Int]$Script:Confirm
        )

        #region [Function Setup] -------------------------------------------------------------------------------------

            #Debug info to help with troubleshooting. Provides detailed variable information to better understand how the function was called.
            Write-nLog -Type:'Debug' -Message:"Function invocation; {$($MyInvocation.line.trim() -replace ('`r`n',':'))}"
            (Get-Variable -Scope:'Local' -Include:@($MyInvocation.MyCommand.Parameters.keys)|
                ForEach-Object { Write-nLog -Type:'Debug' -Message:"Function Param '$($_.name)' = '$($_.Value)'" })

            IF (-Not $PSBoundParameters.ContainsKey('Verbose')) {
                Set-Variable -Name:'Verbose' -Value:([Bool]$Script:Verbose)
            }

            New-Variable -Name:'varSplat' -Value:@{'Verbose'=$Verbose;Force=$True}
            New-Variable -Name:'verSplat' -Value:@{'Verbose'=$Verbose}

            Trap {
                $Line = [Int]([regex]::Match($_.ScriptStackTrace.split("`r`n")[0],
                    '^(?:at .*: line )(?<Line>\d*)(?:.*)$').groups[1].value)
                If ($Script:nLogInitialize) {
                    Write-nLog -Type:'Debug' -Line:$Line -Message:"Failed to execute command: $([string]::join(`"`",$_.InvocationInfo.line.split(`"`n`")))"
                    Write-nLog -Type:'Error' -Line:$Line -Message:"$($_.Exception.Message) [$($_.Exception.GetType().FullName)]"
                } Else {
                    Write-Host -Object "Failed to execute command: $([string]::join(`"`",$_.InvocationInfo.line.split(`"`n`")))"
                    Write-Host -Object "$($_.Exception.Message) [$($_.Exception.GetType().FullName)]"
                }
                Continue
            }

            $ConfirmEnv = '0' -contains $Confim
            $ConfirmChg = '1','2' -contains $Confim

            New-Variable @verSplat -Scope:'Private' -Name:'EndFunction' -Value:([ScriptBlock]::Create({
                Try {$lMSG='Closing RegistrySubKey: {0}'
                    $RegistrySubKey.Close()
                    Write-nLog -Type:'Debug' -Message:$lMSG.Replace('{0}','Success')
                } Catch {Write-Error -ErrorId:'' -Message:$lMSG.Replace('{0}','Failure')}

                Try {$lMSG='Closing RegistryHive: {0}'
                    $RegistryKey.close()
                    Write-nLog -Type:'Debug' -Message:$lMSG.Replace('{0}','Success')
                } Catch {Write-Error -ErrorId:'' -Message:$lMSG.Replace('{0}','Failure')}

                Return $Result
            }))

            New-Variable @varSplat -Name:'HiveTypeDB' -Value:(@{
                'HKEY_USERS'          = [Microsoft.Win32.RegistryHive]::Users
                'HKEY_CLASSES_ROOT'   = [Microsoft.Win32.RegistryHive]::ClassesRoot
                'HKEY_CURRENT_CONFIG' = [Microsoft.Win32.RegistryHive]::CurrentConfig
                'HKEY_CURRENT_USER'   = [Microsoft.Win32.RegistryHive]::CurrentUser
                'HKEY_LOCAL_MACHINE'  = [Microsoft.Win32.RegistryHive]::LocalMachine
            })

        #endregion [Function Setup],#')}]#")}]#'")}]------------------------------------------------------------------

        #region [Parameter Validation] -------------------------------------------------------------------------------
            Set-Variable -Name:'Path' -Value:($Path.Trim("\"))

            Try { $logMessage = 'Attempting to convert DataType from [String] to [Microsoft.Win32.RegistryValueKind]: {0}'
                Set-Variable @varSplat -Name:'DataType' -Value:([Microsoft.Win32.RegistryValueKind]$DataType)
                Write-nLog -Type:'Debug' -Message:$logMessage.Replace('{0}','Success')
            } Catch { Write-Error -ErrorId:'10' -Exception:''}

        #endregion [Parameter Validation],#')}]#")}]#'")}]------------------------------------------------------------

        #region [Variable Initializations] ---------------------------------------------------------------------------
        New-Variable @varSplat -Scope:'Private' -Name:'Variables' -Value:@{'RegistryKey'=[Microsoft.Win32.RegistryKey];
            'RegistrySubKey'=$Null;'RegistrySubKeyKind'=$Null;
        }

        New-Variable @varSplat -Name:'Result' -Value:@{'Changes'=[Int]0;'ExitCode'=[Int]0}

        #endregion [Variable Initializations],#')}]#")}]#'")}]--------------------------------------------------------

        #region [Main Function] --------------------------------------------------------------------------------------

            <#This is custom entry to save several hundred lines of code throughout the script. If this function is used elsewhere it should be removed.
            IF ([String]::IsNullOrWhiteSpace($Script:DefaultUserPath) -eq $False -AND $RegistryHive -eq "HKEY_CURRENT_USER") {
                IF ($Script:TargetUser -eq "Both") {
                    Set-RegistryKey -RegistryHive HKEY_LOCAL_MACHINE -Path "$DefaultUserPath\$Path" -DataType $DataType  -Name $Name -Value $Value -CreateKey $CreateKey -Confim $Confim -FixDataType $FixDataType
                } ElseIF ($Script:TargetUser -eq "DefaultUser") {
                    Set-Variable @vSplat -Name RegistryHive -Value "HKEY_LOCAL_MACHINE"
                    Set-Variable @vSplat -Name Path -Value "$DefaultUserPath\$Path"
                }
            }
            #>

            Try {$lMSG="Connecting to registry hive. [Path: '$RegistryHive']: {0}"
                Set-Variable @varSplat -Name:'RegistryKey' -Value:(
                    [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($HiveTypeDB[$RegistryHive],$env:COMPUTERNAME))
                Write-nLog -Type:'Debug' -Message:$lMSG.Replace('{0}','Success')
            } Catch { Write-Error -ErrorId:'' -Exception:$lMSG.Replace('{0}','Failure') }

            $lMSG="Checking for the existance of registry key [Path: '$RegistryHive\$Path']: {0}"
            If (Test-Path @verSplat -Path:"Registry::$RegistryHive\$Path" -PathType:'Container') {
                Write-nLog -Type:'Debug' -Message:$lMSG.replace('{0}','Found')

                Try { $lMSG = "Attempting to open registry key. [Path: '$RegistryHive\$Path']: {0}"
                    $RegistrySubKey = $RegistryKey.OpenSubKey($Path,$True)
                    Write-nLog -Type:'Debug' -Message:$lMSG.Replace('{0}','Success')
                } Catch { Write-Error -ErrorId:'' -Exception:$lMSG}

            } Else {
                Write-nLog -Type:'Debug' -Message:$lMSG.replace('{0}','Not Found')

                If ($CreateKey) {
                    Try {$lMSG="Creating registry key. [Path: '$RegistryHive\$Path']: {0}"
                        Set-Variable @varSplat -Name:'RegistrySubKey' -Value:($RegistryKey.CreateSubKey($Path))
                        Write-nLog -Type:'Debug' -Message:$lMSG.Replace('{0}','Success')
                    } Catch { Write-Error -ErrorId:'' -Exception:$lMSG}

                } Else { #CreateKey
                    Write-Error -ErrorId:'' -Exception:'Registry key doesn''t exist and ''$CreateKey'' is ''$False''.'
                }
            }


            $lMSG="Checking if key already contains '$Name' property: {0}"
            IF ($RegistrySubKey.GetValueNames() -contains $Name) {
                Write-nLog -Type:'Debug' -Message:$lMSG.replace('{0}','Found')

                Try { $lMSG='Getting RegistrySubKey valuekind: '
                        Set-Variable @varSplat -Name:'RegistrySubKeyKind' -Value:(
                            $RegistrySubKey.GetValueKind("$Name"))
                        Write-nLog -Type:'Debug' -Message:$lMSG.Replace('{0}','Success')
                    } Catch {Write-Error -ErrorId:'' -Message:$lMSG.Replace('{0}','Unable to determine valuekind')}


                IF ($RegistrySubKeyKind -ne $DataType) {
                    Write-nLog -Type:'Info' -Message:"Registry property type is '$($RegistryKey.GetValueKind($Name))' but expected '$($DataType)."
                    If ($FixDataType) {
                        Set-Variable -Name:'KeyAction' -Value:'Replace'
                    } Else {
                        Set-Variable -Name:'KeyAction' -Value:'None'
                    }

                } ElseIF ($RegistrySubKey.GetValue($Name) -ne $Value) {
                    Set-Variable @varSplat -Name:'KeyAction' -Value:'Set'
                } Else {
                    Set-Variable @varSplat -Name:'KeyAction' -Value:'Done'
                }
            } Else {
                Write-nLog -Type:'Debug' -Message:$lMSG.replace('{0}','Not Found')
                Set-Variable @varSplat -Name:'KeyAction' -Value:'Set'
            }


            $lMSG="Begining key action: {0}"
            If ($KeyAction -in @('Create','Set','Replace')) {

                If ($KeyAction -eq 'Replace') {
                    Try { $lMSG="Deleting registry subkey property '$Name': {0}"
                    $RegistrySubKey.DeleteKey("$Name")
                    Write-nLog -Type:'Info' -Message:$lMSG.Replace('{0}','Success')
                    } Catch {Write-Error -ErrorId:'' -Message:$lMSG.Replace('{0}','Failure')}
                }

                Try { $lMSG="Creating registry subkey property '$Name' with value '$Value': {0}"
                    $RegistrySubKey.SetValue($Name,$Value,$DataType)
                    Write-nLog -Type:'Info' -Message:$lMSG.Replace('{0}','Success')
                } Catch {Write-Error -ErrorId:'' -Message:$lMSG.Replace('{0}','Failure')}

                $Result.Changes++
            } ElseIf ($KeyAction -eq 'Done') {
                Write-nLog -Type:'Info' -Message:"Registry key property '$RegistryHive\$Path\$Name' is already set correctly. [Type: $DataType; Value: $Value]"
            } Else {
                Write-Error -ErrorId:'' -Message:"Variable `$KeyAction has unknown value of '$KeyAction'."
            }

            Invoke-Command -NoNewScope -ScriptBlock:$EndFunction
        #endregion [Main Script],#')}]#")}]#'")}]---------------------------------------------------------------------

    }

    Function Get-TargetTPM {
        Param (
            [Parameter(Mandatory=$False,Position=0)]
            $LocalCimSession,
            [Parameter(Mandatory=$False,Position=0)]
            [Switch]$Retry
        )

        If ($PSBoundParameters.Keys -notcontains 'LocalCimSession') {
            New-Variable -Force -Name:'LocalCimSession' -Value:(New-CimSession -ComputerName:"localhost" –SessionOption:(
                New-CimSessionOption –Protocol:'DCOM')
            )
        }

        # Attempt to query TPM information for local system.
        New-Variable -Force -Name:'TPM'  -Value:(New-Object -TypeName:'PSCustomObject')
        New-Variable -Force -Name:'TPMs' -Value:(New-Object -TypeName:'System.Collections.ArrayList')
        New-Variable -Force -Name:'TPMQuery' -Value:(@{
            ClassName  = 'Win32_TPM';
            NameSpace  = 'root\CIMV2\Security\MicrosoftTpm';
            Property   = 'IsActivated_InitialValue','IsEnabled_InitialValue','IsOwned_InitialValue','PhysicalPresenceVersionInfo','SpecVersion',
                         'ManufacturerId','ManufacturerIdTxt','ManufacturerVersion','ManufacturerVersionFull20','ManufacturerVersionInfo'
            CimSession = $LocalCimSession
        })

        Try {
            Get-CimInstance @TPMQuery | Select-Object -Property:($TPMQuery.Property) |ForEach-Object -Process:({$Null = $TPMs.Add([PSCustomObject]@{
                IsActivated_InitialValue = [Bool]$_.IsActivated_InitialValue
                IsEnabled_InitialValue = [Bool]$_.IsEnabled_InitialValue
                IsOwned_InitialValue = [Bool]$_.IsOwned_InitialValue
                PhysicalPresenceVersionInfo = [version]::Parse($_.PhysicalPresenceVersionInfo)
                SpecVersion = (($_.SpecVersion -split ',') | ForEach-Object -Process:({
                    If([Version]::TryParse($_.trim(),[ref]$Null)) {[Version]::Parse($_.Trim())} Else {$_.Trim() -as [Int]}
                }))
                ManufacturerId = $_.ManufacturerId
                ManufacturerIdTxt = $_.ManufacturerIdTxt
                ManufacturerVersion = [Version]::Parse($_.ManufacturerVersion)
                ManufacturerVersionFull20 = [Version]::Parse($_.ManufacturerVersionFull20)
                ManufacturerVersionInfo = $_.ManufacturerVersionInfo
            })})
        } Catch [Microsoft.Management.Infrastructure.CimException] {
            $TPMS = Get-TPMInformation
        } Catch {
            Throw $Error[0]
        }

        If ($Retry) {
            Return $TPMs
        } Else {
            Switch ([Int]$TPMs.Count) {
                0          {}
                1          { $TPM = $TPMs[0] }
                {$_ -ge 2} {
                    #Select TPM with highest TPM compatibility
                    $TPM = $TPMs |Sort-Object -Property:'PhysicalPresenceVersionInfo' |Select -First:1
                }
                Default    {
                    Write-Error -Message:"Unknown value for '`$TPMs'. Value: $($TPMs.tostring())"
                }
            }
            Return $TPM
        }
    }

    Function Start-BdeHdCfg {

        New-Variable -Force -Name:'BdeHdCfg' -Value:(@{
            Version = [Version]$Null
            Status  = 'Unknown'
            Output  = New-Object -TypeName:'System.Collections.ArrayList'
        })

        # Capture raw command output.
        $NUll = & "$env:systemdrive\Windows\System32\BdeHdCfg.exe" -target default -quiet
        New-Variable -Force -Name:CmdOutput -Value:(
            (& "$env:systemdrive\Windows\System32\BdeHdCfg.exe" -target default) |
                ForEach-Object {if (-Not [String]::IsNullOrEmpty($_)) {$_}}
        )

        # Itterate raw command output and process it.
        For ($I=0; $I -lt $CmdOutput.Length; $I++) {
            Switch -Regex ($CmdOutput[$i]) {
                "^Copyright.*$" { $Null = $BdeHdCfg.Output.Add($_)}
                "^BitLocker Drive Preparation Tool version.*$" {
                    $Version = ($CmdOutput[$i] -split ' version ')[1]
                    If ([Version]::TryParse($Version,[ref]$Null)) {
                        $BdeHdCfg.Version = [version]::Parse($Version)
                    }
                    $Null = $BdeHdCfg.Output.Add($_)
                }
                "Initializing, please wait..." { $Null = $BdeHdCfg.Output.Add($_) }
                Default {
                    If (($CmdOutput[$I][$CmdOutput[$I].Length - 1] -ne '.') -and ($CmdOutput[$I+1][0] -cnotmatch "[A-Z]")) {
                        if ((($CmdOutput[$I][$CmdOutput[$I].Length - 1]) -cmatch "[a-z]") -and ($CmdOutput[$I+1][0] -cmatch "[a-z]")) {
                            $Null = $BdeHdCfg.Output.Add("$($CmdOutput[$I]) $($CmdOutput[$I+1])")
                        } Else {
                            $Null = $BdeHdCfg.Output.Add("$($CmdOutput[$I])$($CmdOutput[$I+1])")
                        }
                        $I++
                    } Else {
                        $BdeHdCfg.Output.Add("$($CmdOutput[$I])")
                    }
                }
            }
        }

        # Attempt to determine drive readiness.
        ForEach ($Line in $BdeHdCfg.Output) {
            Switch ($Line) {
                "This computer's hard drive is properly configured for BitLocker. It is not necessary to run BitLocker Setup." {
                    $BdeHdCfg.Status = 'Configured'
                }
                Default {
                    #Write-Information -MessageData "$Line"
                }
            }
        }

        Return $BdeHdCfg

    }

    Function Start-Restart {

        Param(
            [String]$BeginWindow = '23:00',
            [string]$EndWindow = '23:59'
        )

        New-Variable -Force -Name:'Now' -Value:([DateTime]::Now)
        Set-Variable -Force -Name:'BeginWindow' -Value:([datetime]::Parse($BeginWindow))
        Set-Variable -Force -Name:'EndWindow' -Value:([datetime]::Parse($EndWindow))

        If ($Now -ge $BeginWindow -and $Now -le $EndWindow) {
            Write-nLog -Type:'Info' -Message:'Inside of maintenance window; Restarting computer.'
            Restart-Computer -Force -ComputerName:$env:COMPUTERNAME -Delay:'60'
        } Else {
            Write-nLog -Type:'Info' -Message:'Outside of maintenance window.'
        }

    }

#endregion,#')}]#")}]#'")}]

#region----------------------------------------- [Initializations & Prerequisites] -----------------------------------------------

    #region [Universal Error Trapping with easier to understand output] ---------------------------------------------------------
        New-Variable -Name nLogInitialize -Value:$False -Force
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
        Trap {
            if ($nLogInitialize) {
                Write-nLog -Type Debug -Message "Failed to execute command: $([string]::join(`"`",$_.InvocationInfo.line.split(`"`n`")))"
                Write-nLog -Type Error -Message "$($_.Exception.Message) [$($_.Exception.GetType().FullName)]" -Line $_.InvocationInfo.ScriptLineNumber
            } Else {
                Write-Host -Object "Failed to execute command: $([string]::join(`"`",$_.InvocationInfo.line.split(`"`n`")))"
                Write-Host -Object "$($_.Exception.Message) [$($_.Exception.GetType().FullName)]"
            }
            Continue
        }
    #endregion [Universal Error Trapping with easier to understand output],#')}]#")}]#'")}]

    #region [configure environment variables] ---------------------------------------------------------

        #Determine the Log Output Level
        Switch ($LogLevel) {
            "Debug"   {$DebugPreference = 'Continue'        ; $VerbosePreference = 'Continue'        ; $InformationPreference = 'Continue'        ; $WarningPreference = 'Continue'        ; $ErrorPreference = 'Continue'        }
            "Verbose" {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'Continue'        ; $InformationPreference = 'Continue'        ; $WarningPreference = 'Continue'        ; $ErrorPreference = 'Continue'        }
            "Info"    {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'Continue'        ; $WarningPreference = 'Continue'        ; $ErrorPreference = 'Continue'        }
            "Warn"    {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'; $WarningPreference = 'Continue'        ; $ErrorPreference = 'Continue'        }
            "Error"   {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'; $ErrorPreference = 'Continue'        }
            "Off"     {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'; $ErrorPreference = 'SilentlyContinue'}
        }

        #Converts Verbose Prefernce to bool so it can be used in "-Verbose:" arguments.
        [Bool]$Verbose = ($VerbosePreference -eq 'Continue')

        #Create CommandSplat variable.
        New-Variable -Force -Verbose:$Verbose -Name CommandSplat -Value (New-Object -TypeName HashTable -ArgumentList 0,([StringComparer]::OrdinalIgnoreCase))
        $CommandSplat.Add('Verbose',$Verbose)

        #Set Set Debug Level
        Switch ($Debugger) {
            0       { $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Inquire  ; Set-StrictMode -Version Latest ; Set-PsDebug -Trace 2}
            1       { $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Inquire  ; Set-StrictMode -Version Latest ; Set-PsDebug -Trace 1}
            2       { $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Inquire  ; Set-StrictMode -Version Latest }
            Default { $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop     }
        }
    #endregion [configure environment variables],#')}]#")}]#'")}]

    #region [Determine ScriptEnv properties] ---------------------------------------------------------
        #Variable used to store certain sometimes useful script related information.
        New-Variable -Name ScriptEnv -Force -scope Script -value @{
            RunMethod      = [String]::Empty
            Interactive    = [Bool]$([Environment]::GetCommandLineArgs().Contains('-NonInteractive') -or ([Environment]::UserInteractive -EQ $False))
            IsAdmin        = [Bool]$((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
            Parameters     = New-Object -TypeName "System.Text.StringBuilder"
            Script         = [System.IO.FileInfo]$Null
            Powershellpath = New-object -TypeName 'System.io.fileinfo' -ArgumentList (get-command powershell).source
            Variables      = New-Object -TypeName 'System.Collections.ArrayList'
        }

        #Create a proper parameter string.
        ForEach ($Parameter in $Script:PSBoundParameters.GetEnumerator()) {
            [void]$ScriptEnv.Parameters.Append(" -$($Parameter.key): ""$($Parameter.Value)""")
        }

        #Determine The Environment The Script is Running in.
        IF (Test-Path -Path Variable:PSise) {
            #Running as PSISE
            [String]$ScriptEnv.RunMethod = 'ISE'
            [System.IO.FileInfo]$ScriptEnv.Script = New-Object -TypeName 'System.IO.FileInfo' -ArgumentList $psISE.CurrentFile.FullPath
        } ElseIF (Test-Path -Path Variable:pseditor) {
            #Running as VSCode
            [String]$ScriptEnv.RunMethod = 'VSCode'
            [System.IO.FileInfo]$ScriptEnv.Script = New-Object -TypeName 'System.IO.FileInfo' -ArgumentList $pseditor.GetEditorContext().CurrentFile.Path
        } Else {
            #Running as AzureDevOps or Powershell
            [String]$ScriptEnv.RunMethod = 'ADPS'
            IF ($Host.Version.Major -GE 3) {
                [System.IO.FileInfo]$ScriptEnv.Script = New-Object -TypeName 'System.IO.FileInfo' -ArgumentList $PSCommandPath
            } Else {
                [System.IO.FileInfo]$ScriptEnv.Script = New-Object -TypeName 'System.IO.FileInfo' -ArgumentList $MyInvocation.MyCommand.Definition
            }
        }
    #endregion [Determine ScriptEnv properties],#')}]#")}]#'")}]

    #region [If Administrator check] ---------------------------------------------------------
    #This doesn't work atm.
    If ($ScriptConfig.RequreAdmin -eq $True) {
        If ($ScriptEnv.IsAdmin -eq $False) {
            Write-Warning -Message 'Warning: Script not running as administrator, relaunching as administrator.'
            If ($ScriptEnv.RunMethod -eq 'ISE') {
                If ($psISE.CurrentFile.IsUntitled-eq $True) {
                    Write-Error -Message 'Unable to elevate script, please save script before attempting to run.'
                    break
                } Else {
                    If ($psISE.CurrentFile.IsSaved -eq $False) {
                        Write-Warning 'ISE Script unsaved, unexpected results may occur.'
                    }
                }
            }
            $Process = [System.Diagnostics.Process]::new()
            $Process.StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
            $Process.StartInfo.Arguments = "-NoLogo -ExecutionPolicy Bypass -noprofile -command &{start-process '$($ScriptEnv.Powershellpath)' {$runthis} -verb runas}"
            $Process.StartInfo.FileName = $ScriptEnv.Powershellpath
            $Process.startinfo.WorkingDirectory = $ScriptEnv.ScriptDir
            $Process.StartInfo.UseShellExecute = $False
            $Process.StartInfo.CreateNoWindow  = $True
            $Process.StartInfo.RedirectStandardOutput = $True
            $Process.StartInfo.RedirectStandardError = $False
            $Process.StartInfo.RedirectStandardInput = $False
            $Process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
            $Process.StartInfo.LoadUserProfile = $False
            [Void]$Process.Start()
            [Void]$Process.WaitForExit()
            [Void]$Process.Close()
            exit
        }
    }
    #endregion,#')}]#")}]#'")}]

    #Startup Write-nLog function.
    Write-nLog -Initialize -Type Debug -Message "Starting nLog function."-SetLogLevel:$LogLevel -SetWriteHost $True -SetWriteLog $True -SetTimeLocalization Local -SetLogFormat CMTrace

    #region [Script Prerequisits] --------------------------------------------------------------------------------

        New-Variable -Force -Name:'varSplat' -Value:@{'Verbose'=$Verbose;Force=$True}
        New-Variable @varSplat -Name:'RestartRequired' -Value:$False

    #endregion [Script Prerequisits],#')}]#")}]#'")}]-------------------------------------------------------------

    #region [End Script Function] --------------------------------------------------------------------------------
        New-Variable @varSplat -Scope:'Private' -Name:'EndScript' -Value:([ScriptBlock]::Create({
            Write-nLog -Close -Type:'Info' -Message:'Exiting Script'
            Return $Result
        }))
    #endregion [End Script Function],#')}]#")}]#'")}]-------------------------------------------------------------

    #Remove-Variable -Name @('ScriptConfig','ScriptEnv','Process') -Force -ErrorAction SilentlyContinue
#endregion [Initializations & Prerequisites],#')}]#")}]#'")}]

#region ------------------------------------------------- [Main Script] ------------------------------------------

    #region [Loading System Information] -------------------------------------------------------------------------
        Write-nLog -Type:'Info' -Message:'Step 1: Loading system information.'

        Try {$lMSG = 'Loading Bitlocker Volume information: {0}'
            New-Variable @varSplat -Name:'BitLockerVolume' -Value:(Get-BitLockerVolume -MountPoint:$env:SystemDrive)
            Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
        } Catch {Write-Error -ErrorId:'20' -Message:($lMSG -f 'Failure')}

        Try {$lMSG = 'Initializing LocalCimSession; speeds up CimInstance Calls: {0}'
            New-Variable @varSplat -Name:'LocalCimSession' -Value:(
                New-CimSession -ComputerName:"localhost" –SessionOption (New-CimSessionOption –Protocol:'DCOM'))
            Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
        } Catch {Write-Error -ErrorId:'21' -Message:($lMSG -f 'Failure')}

        #region [Loading & Validating Win32_OperatingSystem Info] ------------------------------------------------
            # Build Win32_OperatingSystem query splat.
            New-Variable @varSplat -Name:'Win32OSQuery' -Value:(@{
                ClassName  = 'Win32_OperatingSystem';
                NameSpace  = 'root\CIMV2';
                Property   = 'BuildNumber','Caption','Description','OSArchitecture','OSType','Version',
                            'PortableOperatingSystem','ProductType','SystemDrive','WindowsDirectory'
                CimSession = $LocalCimSession
            })

            Try {$lMSG = 'Querying Win32_OperatingSystem information: {0}'
                New-Variable @varSplat -Name:'OperatingSystem' -Value:(Get-CimInstance @Win32OSQuery |
                    Select-Object -Property:$Win32OSQuery.Property)
                Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
            } Catch {Write-Error -ErrorId:'22' -Message:($lMSG -f 'Failure')}

            $lMSG='Checking if Windows OS supports bitlocker encryption: {0}'
            If ($OperatingSystem.Version -Match "^((6\.[2|3])|1[0|1]\.0)(.[0-9]+)*$") {
                Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
            } Else {
                Write-Error -ErrorId:'23' -Message:($lMSG -f 'Failure')
            }

            $lMSG='Checking if Windows OS role is Workstation: {0}'
            If ($OperatingSystem.ProductType -eq 1) {
                Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
            } Else {
                Write-Error -ErrorId:'24' -Message:($lMSG -f 'Failure')
            }
        #endregion [Loading & Validating Win32_OperatingSystem Info] ---------------------------------------------

        #region [Loading & Validating Win32_ComputerSystem Info] -------------------------------------------------
            # Build Win32_ComputerSystem query splat.
            New-Variable @varSplat -Name Win32CSQuery -Value @{
                ClassName  = 'Win32_ComputerSystem';
                NameSpace  = 'root/CIMV2';
                Property   = 'Manufacturer','Model'
                CimSession = $LocalCimSession
            }

            Try {$lMSG = 'Querying Win32_ComputerSystem information: {0}'
                New-Variable @varSplat -Name:'ComputerSystem' -Value:(Get-CimInstance @Win32CSQuery |
                    Select-Object -Property:$Win32CSQuery.Property)
                Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
            } Catch {Write-Error -ErrorId:'25' -Message:($lMSG -f 'Failure')}
        #endregion [Loading & Validating Win32_ComputerSystem Info] ----------------------------------------------

        #region [Loading & Validating BDEHDCFG] ------------------------------------------------------------------
            Try {$lMSG = 'Loading BDEHDCFG state: {0}'
                New-Variable @varSplat -Name:'BdeHdCfg' -Value:(Start-BdeHdCfg)
                Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
            } Catch {Write-Error -ErrorId:'26' -Message:($lMSG -f 'Failure')}
        #endregion [Loading & Validating BDEHDCFG] ---------------------------------------------------------------

        #region [Loading & Validating TPM] -----------------------------------------------------------------------
            Try {$lMSG = 'Loading TPM information: {0}'
                New-Variable @varSplat -Name:'TPM' -Value:(Get-TargetTPM)
                Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
            } Catch {Write-Error -ErrorId:'27' -Message:($lMSG -f 'Failure')}

            $lMSG='Checking if TPM was found: {0}'
            If (-Not [String]::IsNullOrEmpty($TPM)) {
                Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Pass')

                $lMSG='Checking TPM information meets minimum version of 1.2: {0}'
                If ($TPM.PhysicalPresenceVersionInfo -ge '1.2') {
                    Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Pass')
                } Else {
                    Write-Error -ErrorId:'29' -Message:($lMSG -f 'Failure')
                }
            } Else {
                Write-Error -ErrorId:'28' -Message:($lMSG -f 'Failure')
            }

            Try {$lMSG = 'Checking TPM initialization status: {0}'
                $TPM | Add-Member -Force -MemberType:'NoteProperty' -Name:'InitializeStatus' -Value:(
                    [PSObject]@(Initialize-Tpm))
                Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
            } Catch {Write-Error -ErrorId:'30' -Message:($lMSG -f 'Failure')}
        #endregion [Loading & Validating TPM] --------------------------------------------------------------------

    #endregion [Loading System Information] ----------------------------------------------------------------------

    #region [Ensure Bitlocker OS Volume Readiness] ---------------------------------------------------------------

        If ($BdeHdCfg.Status -ne 'Configured') {
            Write-nLog -Type:'Warning' -Message:'This functionality is not very robust, may not work.'
            Try {$lMSG='Ensuring Defrag service is enabled:'
                Get-Service -Name:'defragsvc' | Set-Service -Status:'Running'
                Write-nLog -Type:'Info' -Message:($lMSG -f 'Success')
            } Catch {Write-Error -ErrorId:'30' -Message:($lMSG -f 'Failure')}

            Try {$lMSG='Attempting to create Bitlocker partition on OS drive:'
                BdeHdCfg -target $env:SystemDrive shrink -quiet
                Write-nLog -Type:'Info' -Message:($lMSG -f 'Success')
                $RestartRequired = $True
            } Catch {Write-Error -ErrorId:'30' -Message:($lMSG -f 'Failure')}
        }

        If ($RestartRequired) { Start-Restart; Invoke-Command -ScriptBlock:$EndScript -NoNewScope}
    #endregion [Ensure Bitlocker OS Volume Readiness] ------------------------------------------------------------

    #region [Initialize TPM] -------------------------------------------------------------------------------------

        Write-nLog -Type:'Info' -Message:('TPM Ititalized: {0}' -f $TPM.IsEnabled_InitialValue)
        If ($TPM.IsEnabled_InitialValue -eq $False) {
            Try { $lMSG='Initializing TPM: {0}'
                Initialize-Tpm -AllowClear -AllowPhysicalPresence
                Write-nLog -Type:'Info' -Message:($lMSG -f 'Success')
            } Catch {
                Write-Error -ErrorId:'31' -Message:($lMSG -f 'Failure')
            }
        }

    #endregion [Initialize TPM],#')}]#")}]#'")}] -----------------------------------------------------------------

    #region [Configure Bitlocker Settings] -----------------------------------------------------------------------
        New-Variable -Force -Name:'BitlockerSettings' -Value:@(
            @('ActiveDirectoryBackup','1'),@('RequireActiveDirectoryBackup','1'),@('OSRecoveryPassword','2'),
            @('ActiveDirectoryInfoToStore','1'), @('EncryptionMethodNoDiffuser','3'),@('OSRecoveryKey','2'),
            @('EncryptionMethodWithXtsOs','6'),@('EncryptionMethodWithXtsFdv','6'),@('OSManageDRA','0'),
            @('EncryptionMethodWithXtsRdv','3'),@('EncryptionMethod','3'),@('FDVRequireActiveDirectoryBackup','1')
            @('OSHideRecoveryPage','1'),@('OSActiveDirectoryBackup','1'),@('OSActiveDirectoryInfoToStore','1')
            @('OSRequireActiveDirectoryBackup','1'),@('OSAllowSecureBootForIntegrity','1'),@('OSRecovery','1'),
            @('FDVManageDRA','0'),@('FDVRecoveryPassword','2'),@('FDVRecoveryKey','2'),@('FDVRecovery','1'),
            @('FDVActiveDirectoryBackup','1'),@('FDVActiveDirectoryInfoToStore','1'),@('OSEncryptionType','1')
            @('FDVEncryptionType','1'),@('FDVHideRecoveryPage','1')
        )

        #Ensure Registry is set properly.
        New-Variable @varSplat -Name:'RegistryChanges' -Value:([Int]0)
        ForEach ($Setting in $BitLockerSettings) {
            $RegistryChanges += (Set-RegistryKey -DataType:'DWORD' -Name:$Setting[0] -Value:$Setting[1] `
                -RegistryHive:'HKEY_LOCAL_MACHINE' -Path:'SOFTWARE\Policies\Microsoft\FVE').changes
        }

        If ($RegistryChanges -gt 0) { $RestartRequired = $True }

        If ($RestartRequired) { Start-Restart; Invoke-Command -ScriptBlock:$EndScript -NoNewScope}

    #endregion [Configure Bitlocker],#')}]#")}]#'")}] ------------------------------------------------------------

    #region [Determine Bitlocker Actions] ------------------------------------------------------------------------

        If (@('EncryptionInProgress','FullyEncrypted') -contains $BitLockerVolume.VolumeStatus) {

            $lMSG='Validating FIPS compliant Bitlocker encryption method: {0} [{1}]' -f '{0}',$BitLockerVolume.EncryptionMethod
            If (@('Aes256') -contains $BitLockerVolume.EncryptionMethod) {
                Write-nLog -Type:'Info' -Message:($lMSG -f 'Pass')
            } Else {
                Set-Variable @varSplat -Name:'blAction' -Value:'Decrypt'
                Write-nLog -Type:'Warning' -Message:($lMSG -f 'Failure')
            }

        } ElseIf (@('FullyDecrypted') -contains $BitLockerVolume.VolumeStatus) {
            Set-Variable @varSplat -Name:'blAction' -Value:'Encrypt'
        } Else {
            Write-Error -ErrorId:'33' -Message:'Unknown Bitlocker Volume Status: {0}' -f $BitLockerVolume.VolumeStatus
        }

        Try {$lMSG = 'Loading Bitlocker Volume information: {0}'
            Set-Variable @varSplat -Name:'BitLockerVolume' -Value:(Get-BitLockerVolume -MountPoint:$env:SystemDrive)
            Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
        } Catch {Write-Error -ErrorId:'20' -Message:($lMSG -f 'Failure')}

    #endregion [Determine Bitlocker Actions],#')}]#")}]#'")}] ----------------------------------------------------

    #region [Execute Needed Bitlocker Actions] -------------------------------------------------------------------
        Switch ($blAction) {
            'Encrypt' {
                $BitLockerVolume.KeyProtector.Where({$_.KeyProtectorType -eq 'RecoveryPassword'}) |ForEach-Object {
                    Try {$lMSG='Clearing obsolete RecoveryPassword protectors: {0}'
                        Remove-BitLockerKeyProtector -MountPoint:$env:SystemDrive -KeyProtectorId:$_.KeyProtectorID
                        Write-nLog -Type:'Info' -Message:($lMSG -f 'Success')
                    } Catch {Write-Error -ErrorId:'31' -Message:($lMSG -f 'Failure')}
                }

                If ($BitLockerVolume.KeyProtector.Where({$_.KeyProtectorType -eq 'Tpm'}).count -eq 0) {
                    Try {$lMSG='Adding TPM protector: {0}'
                    [void]($Null=(Add-BitLockerKeyProtector -MountPoint:$env:SystemDrive -TpmProtector)|Out-Null)
                    Write-nLog -Type:'Info' -Message:($lMSG -f 'Success')
                    } Catch {Write-Error -ErrorId:'33' -Message:($lMSG -f 'Failure')}
                }

                Try {$lMSG='Enabling Bitlocker: {0}'
                    Enable-BitLocker -MountPoint:$env:SystemDrive -EncryptionMethod:'Aes256' -RecoveryPasswordProtector
                    Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
                } Catch {Write-Error -ErrorId:'34' -Message:($lMSG -f 'Failure')}

            }

            'Decrypt' {
                Try {$lMSG = 'Disabling Bitlocker Encryption: {0}'
                    Disable-BitLocker -MountPoint:$env:SystemDrive
                    Write-nLog -Type:'Info' -Message:$lMSG.replace('{0}','Success')
                } Catch {Write-Error -ErrorId:'34' -Message:($lMSG -f 'Failure')}
            }

            default {}
        }


    #endregion [Execute Needed Bitlocker Actions] -------------------------------------------------------------------

    #region [Backup Bitlocker Recovery Key] ----------------------------------------------------------------------
        #Ensure each protector is backed up to Active Directory
        ForEach ($Protector in $BitLockerVolume.KeyProtector.Where({$_.KeyProtectorType -eq 'RecoveryPassword'})) {
            Try {$lMSG='Backing up RecoveryPassword to Active Directory: {0}'
                $Null = (Backup-BitLockerKeyProtector -MountPoint:$env:SystemDrive -KeyProtectorId:$Protector.KeyProtectorID)
                Write-nLog -Type:'Info' -Message:($lMSG -f 'Success')
            } Catch {Write-Error -ErrorId:'30' -Message:$lMSG.replace('{0}','Failure')}
        }

        If ($RestartRequired) { Start-Restart; Invoke-Command -ScriptBlock:$EndScript -NoNewScope}
    #endregion [Process Header],#')}]#")}]#'")}] -----------------------------------------------------------------

#endregion [Main Script],#')}]#")}]#'")}]

function Find-AdmNamespaceCollisions {
    [CmdletBinding()]
    param (
        # Specifies a path to one or more locations.
        [Parameter(Position=0,
                   Mandatory=$true,
                   ParameterSetName="Files",
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations containing ADMX/ADML files")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [string[]] $Path,
        
        # String to match on
        [Parameter(Position=1,Mandatory=$true)]
        [Alias("SearchString","Namespace")]
        [String] $String,

        # File Extensions to search
        [Parameter(Position=2)]
        [ValidateSet("ADMX","ADML","Both")]
        [String] $Extension
    )
    
    begin {
        [ARRAY]$searchFiles = @()
        [ARRAY]$FileMatches = @()
        
        If (!($PSBoundParameters['Extension']) -OR $Extension -like 'Both') {
            $ExtensionPattern = '\.admx|\.adml'
        }
        Else {
            $ExtensionPattern = "\.$($Extension)"
        }

        $Pattern = [REGEX]::Escape($string)

    }
    
    process {
        ForEach ($tempPath in $Path) {
            Try {
                Get-ChildItem -File -Recurse -Path $tempPath -ErrorAction Stop | Where-Object {$_.Extension -match $ExtensionPattern} | 
                    ForEach-Object {[ARRAY]$searchFiles += $_}
            }
            Catch {
                Write-Warning "Error searching for child items in path: '$tempPath' - exception: $($_.Exception.Message)"
            }
        }

        If ($searchFiles.Count -lt 1) {
            Write-Warning "No files matching extension filter found in path: '$($Path -join "','")'"
        }
        Else {
            Write-Verbose "Searching $($SearchFiles.Count) files for string: '$string'"
            ForEach ($file in $searchFiles) {
                $Content = Get-Content -Path $file.FullName
                $matchFound = $false
                $i=0
                ForEach ($Line in $Content) {
                    $i++
                    
                    If ($line -match $Pattern) {
                        If ($matchFound -ne $true) {
                            Write-Host "Match Found In File: " -NoNewline
                            Write-Host "'$($file.FullName)'" -ForegroundColor Red
                        }
                        $matchFound = $true
                        Write-Host "`t[Line $($i)]" -ForegroundColor Cyan -NoNewline
                        Write-Host "`t $($line.Trim())" -ForegroundColor Yellow
                        $MatchProperties = [ORDERED]@{
                            'SearchString' = $String
                            'File' = $file.FullName
                            'Length' = $file.Length
                            'CreationTime' = $file.CreationTime
                            'LastWriteTime' = $file.LastWriteTime
                            'Line' = $i
                            'Content' = $line.Trim()
                        }
                        [ARRAY]$FileMatches += New-Object -TypeName PSObject -Property $MatchProperties
                    }
                }
            }
        }
    }
    
    end {
        Return $fileMatches
    }
}

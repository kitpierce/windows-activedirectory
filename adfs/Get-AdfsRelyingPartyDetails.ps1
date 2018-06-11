Function Get-AdfsRelyingPartyDetails {
    [CmdletBinding()]
    Param
    (
        [Parameter(Position=0, Mandatory = $False, HelpMessage="Relying Party name(s) to include", ValueFromPipeline = $true)] [ALIAS("Name")] [STRING[]] $RelyingPartyName,
        [Parameter(Position=1, Mandatory = $False, HelpMessage="ADFS server name", ValueFromPipeline = $true)] $ADFSServer = $($env:COMPUTERNAME)
    )
     
    BEGIN {
        $ErrorActionPreference = "Stop"
        $Results = @()
 
        ## Commonly referenced relying party properties
        ## Note: this variable is not used in this script version, but included for future reference
        $collectProps = 'Name', 'WSFedEndpoint', 'Identifier', 'MetadataUrl', 'IssuanceTransformRules', 'ConflictWithPublishedPolicy', 'Enabled', 'MonitoringEnabled',
                'AutoUpdateEnabled', 'LastMonitoredTime', 'LastUpdateTime', 'NotBeforeSkew', 'EncryptClaims', 'ProtocolProfile', 'AllowedClientTypes',
                'TokenLifetime', 'IssueOAuthRefreshTokensTo', 'RequestSigningCertificate', 'EncryptionCertificate', 'Notes'
         
        $certProps = "Subject","Issuer","NotBefore","NotAfter","Thumbprint","Handle","SerialNumber","Version"
 
    }
     
    PROCESS {
        # Get all relying party details from ADFS
        $allRelyingParties = Invoke-Command -ErrorAction Stop -ComputerName $ADFSServer -scriptblock {Get-ADFSRelyingPartyTrust | Select-Object -Property * | Sort Name}
 
        # If 'RelyingPartyName' parameter was passed, create RegEx filter and apply filter to 'Name' property
        If ($RelyingPartyName) {
            [REGEX]$RPNameRegex = $($relyingPartyName | % { [REGEX]::Escape($_) }) -join '|'
            $scopedRelyingParties = $allRelyingParties  | Where-Object {$_.Name -match $RPNameRegex}
        }
        # If not, return unfiltered relying party list
        Else { $scopedRelyingParties = $allRelyingParties }
 
        # Iterate through relying parties
        ForEach($party in $scopedRelyingParties) {
            Write-Verbose "Processing Relying Party: '$($party.Name.trim())'"
  
            Try {
                # Define basic relying party properties to collect
                $baseProps = [ORDERED]@{
                        Name                  = $party.Name
                        WSFedEndpoint         = $party.WSFedEndpoint
                        MetadataUrl           = $party.MetadataUrl
                        Enabled               = $party.Enabled
                        MonitoringEnabled     = $party.MonitoringEnabled
                        AutoUpdateEnabled     = $party.AutoUpdateEnabled
                        LastMonitoredTime     = $party.LastMonitoredTime
                        LastUpdateTime        = $party.LastUpdateTime
                        NotBeforeSkew         = $party.NotBeforeSkew
                        ProtocolProfile       = $party.ProtocolProfile
                        TokenLifetime         = $party.TokenLifetime
                        Notes                 = $party.Notes
                }
 
                # Collect basic properties for relying party
                $RPObj = New-Object PSObject -Property $baseProps
 
                ForEach ($certType in $("RequestSigningCertificate","EncryptionCertificate")) {
                    # Set friendly certificate-type name for property name
                    If ($certType -like "RequestSigningCertificate") { $certName = "SigningCert"}
                    ElseIf ($certType -like "EncryptionCertificate") { $certName = "EncryptionCert"}
 
                    # Collect properties from certificate
                    $certFound = $false
                    ForEach ($certProp in $certProps) {
                        $certPropName = "$($certName)_$($certProp)"    
                        If ($Party.$certType.$certProp) {
                            $certFound = $true
                            $tempPropVal = $party.$certType.$certProp
                        }
                        Else { $tempPropVal = "" }
                        $RPObj | Add-Member -MemberType NoteProperty -Name $certPropName -Value $party.$certType.$certProp
                    }
                    If ($certFound -eq $true) { Write-Debug "Found '$certType' certificate" }
 
                    # Calculate certificate expiration days
                    If ($($party.$certType.NotAfter)) {
                        $tempExpiration = $($party.$certType.NotAfter)
                        $certTTL = $($(Get-Date) - $tempExpiration).Days * (-1)
                    }
                    Else { $certTTL = "Null" }
                    $RPObj | Add-Member -MemberType NoteProperty -Name "$($certName)_ExpirationInDays" -Value $certTTL
                }
                 
                # Add RelyingParty object to collector
                $Results += $RPObj
 
            }
            Catch { $_.Exception.Message; Continue }
        }
    }
    END {
        If($Results) { Return $Results }
        Else { Write-Host "No ADFS Relying Party results found..." }
    }
}

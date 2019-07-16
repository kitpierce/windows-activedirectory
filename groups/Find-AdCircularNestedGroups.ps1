function Find-AdCircularNestedGroups {
    [CmdletBinding()]
    param ()
    
    begin {
        # Modified, debugged, & feature-added version of script found here: 
        # https://gallery.technet.microsoft.com/scriptcenter/fa4ccf4f-712e-459c-88b4-aacdb03a08d0/file/42121/1/CircularNestedGroups.ps1
        $ErrorActionPreference = 'Stop'

        if (-not ($MyInvocation.MyCommand.Name)) {$callName = ''}
        else {$callName = "[$($MyInvocation.MyCommand.Name)] "}

        $GroupProperties = 'Member','MemberOf'

        # Create hashtable to collect groups and their direct group members. 
        $script:GroupMembers = @{} 

        #region ## INTERNAL FUNCTIONS ###
        Function Test-Nesting {
            [CmdletBinding()]
            param (
                # Type Of Objects To Collect
                [Parameter(Position=0,Mandatory)]
                [String] $Group,
        
                [Parameter(Position=1,Mandatory)]
                [String[]] $Parents
            )
        
            $ErrorActionPreference = 'Stop'
        
            if (-not ($MyInvocation.MyCommand.Name)) {$callName = ''}
            else {$callName = "[$($MyInvocation.MyCommand.Name)] "}
        
            # Recursive function to enumerate group members of a group. 
            # $Group is the group whose membership is being evaluated. 
            # $Parents is an array of all parent groups of $Group. 
            # $GroupMembers is the hashtable of all groups and their group members.  (must be script-scope)
            # If any group member matches any of the parents, we have 
            # detected an instance of circular nesting. 
         
            # Enumerate all group members of $Group. 
            $Members = $Script:GroupMembers[$Group]
        
            ForEach ($Member In $Members) {
                # Check if this group matches any parent group. 
                ForEach ($Parent In $Parents) { 
                    If ($Member -eq $Parent) { 
                        # This is a circular nested group!
                        # Return group to avoid infinite loop.
                        Write-Verbose "${callName}Found circular-nested group: '$Parent'"
                        Return $Parent
                    } 
                } 
                # Check all group members for group membership. 
                If ($Script:GroupMembers.ContainsKey($Member)) { 
                    # Add this member to array of parent groups. 
                    # However, this is not a parent for siblings. 
                    # Recursively call function to find nested groups. 
                    $Temp = $Parents 
                    Test-Nesting $Member ($Temp += $Member) 
                } 
            } 
        }
        
        function New-LdapSearch {
            [CmdletBinding()]
            param (
                # Type Of Objects To Collect
                [Parameter(Position=0,Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
                [ValidateSet('User','Group','Computer','ForeignSecurityPrincipal','Contact','ServiceConnectionPoint','msExchActiveSyncDevices',
                    'Container','OrganizationalUnit','PrintQueue','GroupPolicyContainer','TrustedDomain')]
                [Alias('ObjectClass')]            
                [String[]] $Class,
        
                [Parameter(Position=1)]
                [String[]] $Properties,
        
                [Parameter(Position=2)]
                [Int] $Count = [INT]::MaxValue
            )
            
            begin {
                $ErrorActionPreference = 'Stop'
        
                if (-not ($MyInvocation.MyCommand.Name)) {$callName = ''}
                else {$callName = "[$($MyInvocation.MyCommand.Name)] "}
        
                if ($Properties -contains 'All' -OR $Properties -contains '*') {
                    Write-Warning "${callName}Specifying all properties will adversely impact performance."
                    Write-Verbose "${callName}Consider using object-specific ActiveDirectory commandlet with appropriate filters..."
                }
        
                if (-not $PSBoundParameters.ContainsKey('Count')) {
                    Write-Verbose "${callName}Setting maximum value for search results: '$Count' - use 'Count' parameter to limit"
                }
                
                $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $Root = $Domain.GetDirectoryEntry() 
                $DomainName = $Domain.Name.ToUpper()
        
                $WriteRed = @{ 'NoNewLine' = $true; 'ForegroundColor' = 'Red' }
                $WriteRedEnd = @{ 'NoNewLine' = $false; 'ForegroundColor' = 'Red' }
        
                # Every searcher will collect 'ObjectClass' & 'DistinguishedName'
                # Add an array of additional properties to collect for each type
                $AddPropertyTable = @{
                    'Group' = @('Member');
                    'User' = @('MemberOf');
                    'Computer' = @('MemberOf');
                }
            }
            
            process {
                forEach ($tempClass in $Class) {
                    $i=0
        
                    # Define properties to collect based on ObjectClass using internal
                    # variable 'AddPropertyTable' & user-provided parameter 'Properties'
                    if ($Properties -contains 'All' -OR $Properties -contains '*') {
                        $CollectProps = '*'
                    }
                    else {
                        [ARRAY]$CollectProps = 'ObjectClass','DistinguishedName'
                        $Properties |  ForEach-Object {
                            if ($_ -ne $Null -AND $CollectProps -notcontains "$_") {
                                [ARRAY]$CollectProps += "$_"
                            }
                        }
                        
                        $AddPropertyTable["$tempClass"] |  ForEach-Object {
                            if ($_ -ne $Null -AND $CollectProps -notcontains "$_") {
                                [ARRAY]$CollectProps += "$_"
                            }
                        }
                    }
        
                    Write-Host "${callName}Collecting " -NoNewline; 
                    Write-Host "'$tempClass'" @WriteRed
                    Write-Host " Objects In Domain: " -NoNewline
                    Write-Host "'$DomainName'" @WriteRedEnd
        
                    Write-Verbose "${callName}Collecting '$tempClass' objects with property set: '$($CollectProps -join "','")'"
        
                    # Create DirectorySearcher object
                    $Searcher = [System.DirectoryServices.DirectorySearcher]$Root
        
                    # Set DirectorySearcher's options
                    $filter = "(objectCategory=$tempClass)"
                    $Searcher.Filter = $Filter 
                    $Searcher.PageSize = 200 
                    $Searcher.SizeLimit = $Count
                    $Searcher.SearchScope = "subtree" 
                    $CollectProps | Where-Object {$_} | ForEach-Object {
                        $Searcher.PropertiesToLoad.Add("$_") > $Null 
                    }
        
                    # Invoke DirectorySearcher & return objects to pipeline
                    $Searcher.FindAll() | ForEach-Object {
                        $i++
                        $_
                    }
                    Write-Verbose "${callName}Found ${i} '$tempClass' objects in domain: '$($domain.Name.ToUpper())'"
                }
            }
        }
        #endregion
    }
    
    process {
        Write-Host "${callName}Query LDAP for all ADGroup objects"
        $AllGroups = New-LdapSearch -Class Group -Properties Member | Sort-Object -Property Path
        $grpCount = $AllGroups.Count

        # Enumerate groups and populate Hash table. The key value will be 
        # the Distinguished Name of the group. The item value will be an array 
        # of the Distinguished Names of all members o$ref the group that are groups. 
        # The item value starts out as an empty array, since we don't know yet 
        # which members are groups. 
        Write-Host "${callName}Creating ${grpCount}-member hashtable using ADGroups' DistinguishedName as key"
        ForEach ($Group In $AllGroups) {
            $DN = [string]$Group.Properties.Item("distinguishedName")
            $Script:GroupMembers.Add($DN, @()) 
        } 
        
        # Enumerate the groups again to populate the item value arrays. 
        # Now we can check each member to see if it is a group. 
        Write-Host "${callName}Updating hashtable with value of each key's 'Member' group objects"
        ForEach ($Group In $AllGroups) { 
            $DN = [string]$Group.properties.Item("distinguishedName") 
            [ARRAY]$Members = @($Group.properties.Item("member")) | Where-Object {$script:GroupMembers.ContainsKey($_)}
            # Enumerate the members of the group. 
            if ($members.Count -gt 0) {
                Write-Verbose "${callName}Group has $($members.Count) group(s) in 'Member' property: '$DN'"        
            }
            $Script:GroupMembers[$DN] = $Members
        }

        # Enumerate all groups and check group membership of each. 
        Write-Host "${callName}Checking all groups for circular membership"
        [ARRAY]$nestedGroups = @()
        ForEach ($handle in $script:GroupMembers.GetEnumerator()) {
            $Group = $handle.Name
            $nestFound = Test-Nesting $Group @($Group)
            if ($nestFound -AND $nestFound -notin $NestedGroups.DistinguishedName) {
                [ARRAY]$nestedGroups += $nestFound | Get-AdGroup -Properties $GroupProperties
            }
        }
    }
    
    end {
        if ($nestedGroups.Count -gt 0) {
            Write-Host "Found $($nestedGroups.Count) AD Group(s) With Circular Membership" -ForegroundColor Red
            $nestedGroups | Sort-Object -Property Name | ForEach-Object {
                Write-Host "`t'$($_.Name)'" -ForegroundColor Cyan -NoNewline
                Write-Host " '$($_.DistinguishedName)'" -ForegroundColor Yellow
            }
        }
        Return $nestedGroups
    }
}


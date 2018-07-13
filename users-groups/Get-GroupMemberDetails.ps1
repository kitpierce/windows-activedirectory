Function Get-GroupMemberDetails {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$False)] [ValidateSet("Members","MemberOf","Both")] 
            [String] $QueryType = "Both",
        [Parameter(Position=1,Mandatory=$False)] [ValidateSet("HashTable","Array")] 
            [String] $ReturnType = "HashTable",
        [Parameter(Position=2,Mandatory=$False)] [ValidateSet("GroupsDirect","AllDirect","UsersRecursive")] 
            [String] $Depth = "GroupsDirect"
    )
    
    If ($IncludeMembership -like "UsersRecursive") {
        Write-Warning "Selecting recursive group membership may SIGNIFICANTLY extend runtime..."
    }

    $exportVariablePrefix = "AdGroup"  # Variable name prefix, only used if 'QueryType' is 'Both' to create global variables

    # Hash table of groups and their direct group members.
    $GroupMembers = @{}
    $GroupMemberOfs = @{}

    # Define LDAP directory search base & options
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $LdapRoot = $Domain.GetDirectoryEntry()
    $Searcher = [System.DirectoryServices.DirectorySearcher]$LdapRoot
    $Searcher.PageSize = 100
    $Searcher.SearchScope = "subtree"
    
    # Define LDAP properties to collect
    $Searcher.PropertiesToLoad.Add("distinguishedName") > $Null
    $Searcher.PropertiesToLoad.Add("member") > $Null
    $Searcher.PropertiesToLoad.Add("memberof") > $Null

    # Filter on all group objects.
    $Searcher.Filter = "(objectCategory=group)"
    
    # Perform search
    $Results = $Searcher.FindAll()
    Write-Host "LDAP Query Of '$($LdapRoot.distinguishedName.ToUpper())' Returned $($Results.Count) Groups - Collecting Details"

    # Enumerate groups and populate a unique hashtable for GroupMembers & GroupMemberOf
    ForEach ($Group In $Results)
    {
        $DN = [string]$Group.properties.Item("distinguishedName")
        $GroupMembers.Add($DN, @())
        $GroupMemberOfs.Add($DN, @())
    }

    # Enumerate the groups again to populate the item value arrays.
    ForEach ($Group In $Results)
    {
        $DN = [string]$Group.properties.Item("distinguishedName")
        
        If ($QueryType -match "Members|Both") {
            # Get recursive membership using 'GetAdGroupMember' with 'Recurse' parameter
            If ($IncludeMembership -like "UsersRecursive") { 
                [ARRAY]$Members = Get-ADGroupMember $DN -Recursive | Select-Object -ExpandProperty DistinguishedName
                Write-Verbose "Found $(($Members.Count).ToString("000")) Recursive User Members Of Group: `t '$DN'"
            }
            # Enumerate the group's 'Member' property
            Else { 
                [ARRAY]$Members = @($Group.properties.Item("member"))
                Write-Verbose "Found $(($Members.Count).ToString("000")) Direct Members Of Group: `t '$DN'"
            }

            ForEach ($Member In $Members) {
                # If 'IncludeMembership' is set to 'GroupsDirect' only, filter members to only include direct membership by a group
                If (($IncludeMembership -like "GroupsDirect") -AND ($GroupMembers.ContainsKey($Member))) { 
                  $GroupMembers[$DN] += $Member 
                }
                Else { $GroupMembers[$DN] += $Member }
            }
        }
        
        If ($QueryType -match "MemberOf|Both") {
            # Enumerate the groups this group is a member of
            [ARRAY]$MemberOfs = @($Group.properties.Item("memberof"))
            Write-Verbose "Found $(($MemberOfs.Count).ToString("000")) Groups In MemberOf Array: `t '$DN'"
            
            ForEach ($MemberOf In $MemberOfs) { $GroupMemberOfs[$DN] += $MemberOf }
        }
    }

    # Create global variables for each collection
    If ($QueryType -like "Both") {
        Set-Variable -Name "$($exportVariablePrefix)Members" -Value $GroupMembers -Scope Global
        Set-Variable -Name "$($exportVariablePrefix)MemberOf" -Value $GroupMemberOfs -Scope Global
        Break
    }
    # Select the hashtable to return & set the value label
    ElseIf ($QueryType -like "Members") { $selectedHash = $GroupMembers; $ValName = "Members" }
    ElseIf ($QueryType -like "MemberOf") { $selectedHash = $GroupMemberOfs; $ValName = "MemberOf" }

    # If user specified 'Array' as return type (rather than default 'Hashtable'), convert hashtable & return array
    If ($ReturnType -like "Array") {
        Write-Verbose "As per 'ReturnType' parameter - converting HashTable to Array"
        [ARRAY]$GroupArray = @()
        $selectedHash.GetEnumerator() | Sort Key | % {
            $props = [ORDERED]@{ 
                'DistinguishedName' = $_.Key;
                'Count' = $_.Value.Count; 
                $ValName = $_.Value 
            }
            [ARRAY]$GroupArray += New-Object -TypeName PSObject -Property $props
        }
        Return $GroupArray
    }
    # Otherwise, return selected hashtable in default format
    Else { Return $selectedHash }
}

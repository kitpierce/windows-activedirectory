#region ActiveDirectory User/Group Hashtable Creation Functions
function Export-DomainGroupHashtable {
    param (
        [Parameter(Position=0,Mandatory=$false)] [ValidateSet('Membership','All')][String]$CreateType = 'All',
        [Parameter(Position=1,Mandatory=$false)] [String[]]$Domain = $(Get-ADDomain).DNSRoot,
        [Parameter(Position=2,Mandatory=$false)] [ValidateSet('Script','Global')][String]$VariableScope = 'Global'
    )

    $tempGroupHash = [ORDERED]@{}
    $tempGroupNameHash = [ORDERED]@{}
    $tempGroupSidHash = [ORDERED]@{}
    Write-Host "Collecting Group Information From $($Domain.Count) Domain(s)"
    ForEach ($tempDomain in $Domain) {
        $tempDomain = $tempDomain.ToUpper()
        Write-Verbose "Collecting group objects from domain: '$tempDomain'"
        $allAdGroups = Get-AdGroup -Filter * -Properties Member -Server $tempDomain | Sort Name

        $i=0
        ForEach ($group in $AllAdGroups) {
            $i++
            Write-Verbose "Getting Details For '$tempDomain' Group $i/$($allAdGroups.Count): '$($group.Name)'"
            [ARRAY]$Members = $group.Member | Sort
            $tempGroupHash.Add($group.DistinguishedName,$Members)
            $tempGroupNameHash.Add($group.DistinguishedName,$group.Name)
            $tempGroupSidHash.Add($group.DistinguishedName,$group.SID)
        }
    }

    Set-Variable -Name GroupHash -Value $tempGroupHash -Scope $VariableScope -Verbose:$Verbose
    If ($CreateType -match 'All') {
        Set-Variable -Name GroupNameHash -Value $tempGroupNameHash -Scope $VariableScope -Verbose:$Verbose
        Set-Variable -Name GroupSidHash -Value $tempGroupSidHash -Scope $VariableScope -Verbose:$Verbose
    }
}

function Export-DomainUserHashtable {
    param (
        [Parameter(Position=0,Mandatory=$false)] [ValidateSet('Membership','All')][String]$CreateType = 'All',
        [Parameter(Position=1,Mandatory=$false)] [String[]]$Domain = $(Get-ADDomain).DNSRoot,
        [Parameter(Position=2,Mandatory=$false)] [ValidateSet('Script','Global')][String]$VariableScope = 'Global'
    )

    $tempUserHash = [ORDERED]@{}
    $tempUserNameHash = [ORDERED]@{}
    $tempUserSidHash = [ORDERED]@{}
    Write-Host "Collecting User Information From $($Domain.Count) Domain(s)"
    ForEach ($tempDomain in $Domain) {
        $tempDomain = $tempDomain.ToUpper()
        Write-Verbose "Collecting user objects from domain: '$tempDomain'"
        $allAdUsers = Get-AdUser -Filter * -Properties MemberOf -Server $tempDomain | Sort Name

        $i=0
        ForEach ($user in $allAdUsers) {
            $i++
            Write-Verbose "Getting Details For '$tempDomain' User $i/$($allAdUsers.Count): '$($user.Name)'"
            [ARRAY]$MemberOf = $user.MemberOf | Sort
            $tempUserHash.Add($user.DistinguishedName,$MemberOf)
            $tempUserNameHash.Add($user.DistinguishedName,$user.Name)
            $tempUserSidHash.Add($user.DistinguishedName,$user.SID)

        }
    }

    Set-Variable -Name UserHash -Value $tempUserHash -Scope $VariableScope -Verbose:$Verbose
    If ($CreateType -match 'All') {
        Set-Variable -Name UserNameHash -Value $tempUserNameHash -Scope $VariableScope -Verbose:$Verbose
        Set-Variable -Name UserSidHash -Value $tempUserSidHash -Scope $VariableScope -Verbose:$Verbose
    }
}
#endregion

#region Nested Group Collection/Testing Functions
function Get-NestedGroupMembership {
    param ([Parameter(Mandatory=$true)] $group)
    $dbgCall = "[$($MyInvocation.MyCommand.CommandType): $($MyInvocation.MyCommand.Name)]"

    [ARRAY]$tempGroupDetails = @()

    If ($group.GetType().Name -like "String") {
        Try {  $DN = Get-AdObject $Group | Select-Object -ExpandProperty DistinguishedName }
        Catch {Write-Warning "$dbgcall Error running 'Get-ADObject' for string: '$Group'";Break}

        Try {
            [ARRAY]$memberGroups = $groupHash[$DN] | Where {$groupHash[$_]} | Sort-Object
            [ARRAY]$memberUsers = $groupHash[$DN] | Where {$userHash[$_]} | Sort-Object
        }
        Catch {Write-Warning "$dbgcall Error querying GroupHash & UserHash for membership: '$($GroupDN)'";Break}

        $innerGroup = New-Object -TypeName PSObject
        $innerGroup | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $dn
        $innerGroup | Add-Member -MemberType NoteProperty -Name Depth -Value 0
        $innerGroup | Add-Member -MemberType NoteProperty -Name Parent -Value $Null
        $innerGroup | Add-Member -MemberType NoteProperty -Name Primary -Value $dn
        $innerGroup | Add-Member -MemberType NoteProperty -Name MemberUsers -Value $memberUsers
        $innerGroup | Add-Member -MemberType NoteProperty -Name MemberGroups -Value $memberGroups
    }

    ElseIf ($group.GetType().Name -like "PSCustomObject") { $innerGroup = $group }
    ElseIf ($group.GetType().BaseType.Name -like "Array") { $innerGroup = $group }
    Else {Write-Warning "Input object is neither string nor PSObject"; Return}

    [ARRAY]$tempGroupDetails += $innerGroup
    ForEach ($member in $innerGroup.MemberGroups) {
        Try {
            [ARRAY]$memberGroups = $groupHash[$member] | Where {$groupHash[$_]} | Sort-Object
            [ARRAY]$memberUsers = $groupHash[$member] | Where {$userHash[$_]} | Sort-Object
        }
        Catch {Write-Warning "$dbgcall Error querying GroupHash & UserHash for membership: '$($member)'";Break}

        $subObj = New-Object -TypeName PSObject
        $subObj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $member
        $subObj | Add-Member -MemberType NoteProperty -Name Depth -Value $($innerGroup.Depth +1)
        $subObj | Add-Member -MemberType NoteProperty -Name Parent -Value $innerGroup.DistinguishedName
        $subObj | Add-Member -MemberType NoteProperty -Name Primary -Value $innerGroup.Primary
        $subObj | Add-Member -MemberType NoteProperty -Name MemberUsers -Value $memberUsers
        $subObj | Add-Member -MemberType NoteProperty -Name MemberGroups -Value $memberGroups
        Write-Debug "$dbgcall Returning sub-group (depth: $($subObj.depth)) to pipeline: $($subObj.DistinguishedName)"
        [ARRAY]$tempGroupDetails += $subObj
        If ($subObj.MemberGroups.Count -gt 0) { Get-NestedGroupMembership $subObj }
    }

    Write-Verbose "$dbgcall Returning $($tempGroupDetails.Count) objects to pipeline"
    Return $tempGroupDetails
}

function Get-ADRecursiveGroupMembership {
    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline,ValueFromPipelineByPropertyName)]
            [Alias("ADObject")]$Identity,
        [Parameter(Position=1,Mandatory=$false)]
            [ValidateSet("Summary","Objects","Both")]
            [Alias("Return")][String]$ReturnType = "Summary",
        [Parameter(Position=2,Mandatory=$false)][ValidateSet("Troubleshoot","Verbose","Silent")]
            [Alias("Feedback")][String]$FeedbackLevel = "Silent",
        [Switch]$ShowDepth
    )

    If ($FeedbackLevel -like "Verbose") {$VerbosePreference="Continue"; $DebugPreference="SilentlyContinue"}
    ElseIf ($FeedbackLevel -like "Troubleshoot") {$VerbosePreference="Continue"; $DebugPreference="Continue"}
    ElseIf ($FeedbackLevel -like "Silent") {$VerbosePreference="SilentlyContinue"; $DebugPreference="SilentlyContinue"}

    $dbgCall = "[$($MyInvocation.MyCommand.CommandType): $($MyInvocation.MyCommand.Name)]"
    [array]$GroupList = @()

    If (!(Get-Module ActiveDirectory)) {
        Write-Verbose "$dbgCall Importing PSModule 'ActiveDirectory'"
        Import-Module ActiveDirectory -Verbose:$false -Debug:$false
    }

    If (!(Get-Variable GroupHash -ErrorAction SilentlyContinue)) {
        Write-Verbose "$dbgCall Creating AD Group Hashtables"
        Export-DomainGroupHashtable -CreateType All
    }
    If (!(Get-Variable UserHash -ErrorAction SilentlyContinue)) {
        Write-Verbose "$dbgCall Creating AD User Hashtables"
        Export-DomainUserHashtable -CreateType All
    }

    If (Get-ADUser $Identity) {
        Write-Verbose "$dbgCall Input is an AD User: '$Identity'"
        $inputObject = Get-ADUser $Identity
        $ObjectDN = $inputObject | Select-Object -ExpandProperty DistinguishedName
        $ObjectType = $inputObject | Select-Object -ExpandProperty ObjectClass
        $ObjectDisplayName = "$($inputObject.Name) [$($inputObject.SamAccountName.ToUpper())]"
        [ARRAY]$DirectMembership = $UserHash[$ObjectDN] | % {$($_ | Out-String).Trim()}
        Write-Verbose "$dbgCall Found $($DirectMembership.Count) direct memberships for user: '$ObjectDisplayName'"
    }
    ElseIf (Get-ADGroup $Identity)  {
        Write-Verbose "$dbgCall Input is an AD Group: '$Identity'"
        $inputObject = Get-AdGroup $Identity
        $ObjectDN = $inputObject | Select-Object -ExpandProperty DistinguishedName
        $ObjectType = $inputObject | Select-Object -ExpandProperty ObjectClass
        $ObjectDisplayName = $inputObject | Select-Object -ExpandProperty Name
        [ARRAY]$DirectMembership = $GroupHash[$ObjectDN] | % {$($_ | Out-String).Trim()}
        Write-Verbose "$dbgCall Found $($DirectMembership.Count) direct memberships of group: '$ObjectDisplayName'"
    }
    Else {Write-Warning "$dbgCall Input object is neither group nor user: '$Identity'"}

    $groupCount = 0
    ForEach ($group in $DirectMembership) {
        $groupCount++
        $groupName = $($group | Out-String).Trim()
        Write-Verbose "$dbgCall Collecting Details For Direct-Membership Group $groupCount/$($directmembership.Count): '$GroupName'"
        $tempGroupList = Get-NestedGroupMembership $GroupName
        $tempGroupList | % {If ($GroupList -notcontains $_) {[ARRAY]$GroupList += $_}}
    }

    If ($ReturnType -Match "Summary|Both") {
        Write-Host "## AD Group Membership Summary For '$($ObjectType.ToUpper())' Object: '$ObjectDisplayName' ##`n"
        Show-GroupNestingSummary -Groups $GroupList -ShowDepth:$ShowDepth
    }

    If ($ReturnType -Match "Objects|Both") {
        Return $GroupList
    }
}
#endregion

#region Group Nesting Reporting/Display Functions
function Show-GroupNestingSummary {
    param (
        [Parameter(Position=0,ValueFromPipeline=$true)] [PSObject[]] $Groups,
        [Switch]$ShowDepth
    )

    BEGIN {
        $dbgCall = "[$($MyInvocation.MyCommand.CommandType): $($MyInvocation.MyCommand.Name)]"
        If (!(Get-Variable GroupNameHash)) {Export-DomainGroupHashtable -CreateType Names -VariableScope Global}
    }
    PROCESS {
        [ARRAY]$baseGroups = $groups | Where-Object {$_.Depth -eq 0} | Sort-Object DistinguishedName
        ForEach ($group in $baseGroups) { Write-GroupName -Name $group -Collection $groups -ShowDepth:$ShowDepth}
    }
}

function Write-GroupName {
    param (
        [Parameter(Position=0,ValueFromPipeline=$true)] [ALIAS("Name")][PSObject[]]$Group,
        [Parameter(Position=1,ValueFromPipeline=$false)] [ALIAS("ObjectCollection","Collection")][PSObject[]]$Groups,
        [Parameter(Position=2,Mandatory=$false)] [String]$Delimiter = '---> ',
        [ALIAS("ShowDepthCount")][Switch]$ShowDepth
    )
    PROCESS {
        ForEach ($innerGroup in $group) {
            $dn = $innerGroup.DistinguishedName
            $name = $GroupNameHash[$innerGroup.DistinguishedName]
            $depth = $innerGroup.Depth

            # Get sub-groups of innerGroup
            [ARRAY]$subGroups = $Groups | Where-Object {$_.Parent -like $dn} |
                Where-Object {$_.Depth -eq $($innerGroup.Depth + 1)} |
                Sort-Object DistinguishedName

            If ($subGroups.Count -eq 1) {
                $txtColor = "Yellow"
                $append = " ($($subGroups.Count) sub-group)"
            }
            ElseIf ($subGroups.Count -gt 1) {
                $txtColor = "Yellow"
                $append = " ($($subGroups.Count) sub-groups)"
            }
            Else {
                $txtColor = "Cyan"
                $append = ""
            }

            If ($depth -lt 1) {
                Write-Host "Direct Group:`t" -NoNewline
                Write-Host "'$Name'" -ForegroundColor Black -BackgroundColor $txtColor -NoNewline
                Write-Host $append
            }
            Else {
                If ($ShowDepth -eq $true) { Write-Host "$(("[D:$($depth.ToString("00"))]").PadLeft(13))`t" -NoNewline }
                Else { Write-Host "`t`t " -NoNewline}
                Write-Host "$($Delimiter * $depth) " -NoNewline
                Write-Host $Name -ForegroundColor $txtColor -NoNewline
                Write-Host $append
            }

            If ($subGroups.Count -gt 0) {
                Write-GroupName -Name $SubGroups -Groups $Groups -ShowDepth:$ShowDepth
            }
        }
    }
}
#endregion

#Requires -Modules AzDevOpsHelper

<#
    .DESCRIPTION
        Applies security permissions to the repositories and branches in a project.

    .NOTES
        This needs a PAT token with the following scopes.
        - Code: Read, write, & manage
        - Graph: Read
        - Identity: Read
        - Project and Team: Read
        - Security: Manage

        To find the bits needed for a Git repository, use the following script:
            (Get-SecurityNamespace -OrganizationUrl $OrganizationUrl -NamespaceName 'Git Repositories').actions

    .PARAMETER OrganizationUrl
        The URL of the organization.

    .PARAMETER ProjectName
        The name of the project to apply branch security against.

    .PARAMETER RepositoryName
        The repository name in the Azure DevOps project.

    .PARAMETER SecurityPolicyDefinition
        The Policy Definition that will be applied to the whole Azure DevOps Project.

        E.g.
            @(
                @{
                    Name     = "Disallow creating new branches in root level of repos (@repository)"
                    Groups   = @("Contributors")
                    AllowBit = 0
                    DenyBit  = 16
                }
                ...
            )

        Note that permission groups on the organization level (e.g. [cmhcvsts]\Project Collection Build Service Accounts)
        should be added in the project such as in the readers group.

    .PARAMETER RepositoryExclusion
        The repositories names that will be ignored when applying the branch policies.

    .EXAMPLE
        ./Set-AzBranchSecurityPolicies.ps1 -ProjectName "CMHC-SCHL - DevOps" -RepositoryName "CMHC-SCHL-DEVOPS-REPORTING"

    .EXAMPLE
        ./Set-AzBranchSecurityPolicies.ps1 -ProjectName "CMHC-SCHL - DevOps" -RepositoryExclusion @("CMHC-SCHL-DEVOPS-Wiki")
#>

[CmdletBinding(DefaultParameterSetName = 'SpecificRepository')]
param(
    [Parameter(Mandatory = $false)]
    [string]$OrganizationUrl = "https://dev.azure.com/cmhcvsts",
    [Parameter(Mandatory = $true)]
    [string]$ProjectName,
    [Parameter(Mandatory = $true, ParameterSetName = 'SpecificRepository')]
    [string]$RepositoryName,
    [Parameter(Mandatory = $false, ParameterSetName = 'MultipleRepository')]
    [string[]]$RepositoryExclusion = @(),
    [Parameter(Mandatory = $false)]
    [object]$SecurityPolicyDefinition = $null,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
)

<#
    .DESCRIPTION
        The default security permissions to the repositories and branches in a Azure DevOps Project.

    .NOTES
        To find the bits needed for a Git repository, use the following script:
            (Get-SecurityNamespace -OrganizationUrl $OrganizationUrl -NamespaceName 'Git Repositories').actions
#>
function Get-BranchSecurityPolicyDefinition {
    $policy = @(
        @{
            Name     = "Disallow creating new branches in root level of repos (@repository)"
            Groups   = @("Contributors")
            AllowBit = 0
            DenyBit  = 16               # CreateBranch
        }
        @{
            Name     = "Allow creating new branches in specific folders under repos (@repository)"
            Groups   = @("Contributors")
            AllowBit = 16               # CreateBranch
            DenyBit  = 0
            Branches = @(
                "feature"
                "release"
                "bugfix"
                "hotfix"
                "bug"
                "ao/feature"
                "ao/release"
                "ao/bugfix"
                "ao/hotfix"
                "ao/bug"
                "user"
            )
        }
        @{
            Name       = "Ensure PR Approvers can delete feature/bug branches"
            MatchGroup = @("PR Approvers")
            AllowBit   = 8              # ForcePush
            DenyBit    = 0
        }
        @{
            Name        = "Contribute to Pull Requests permission to project collection build service accounts"
            AzureDevOps = @("Project Collection Build Service (cmhcvsts)")
            AllowBit    = 16384 + 4     # PullRequestContribute + GenericContribute
            DenyBit     = 0
        }
        @{
            Name     = "Allow Project Administrators to bypass policies when completing pull requests under repos (@repository)"
            Groups   = @("Project Administrators")
            AllowBit = 32768            # PullRequestBypassPolicy
            DenyBit  = 0
        }
    )

    return $policy
}

function Resolve-SecurityDescriptorsFromPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProjectName,
        [Parameter(Mandatory = $true)]
        [object]$PolicyItem,
        [Parameter(Mandatory = $true)]
        [object]$SecurityDescriptors
    )

    $descriptors = @()
    $groups = @()

    # Check if permission group should be matched
    if ($policyItem.MatchGroup) {
        $policyItem.MatchGroup | ForEach-Object {
            $expression = $_
            $groups += $SecurityDescriptors.Keys | Where-Object { $_ -match $expression }
        }
    }

    if ($policyItem.Groups) {
        $groups += $policyItem.Groups
    }

    # Ensure group is fully qualified principalName
    $groups = $groups | ForEach-Object {
        if (-not $_.StartsWith('[')) {
            ("[{0}]\{1}" -f $ProjectName, $_)
        }
        else {
            $_
        }
    }

    # Azure DevOps service accounts does not need a its principal name to be adjusted.
    if ($policyItem.AzureDevOps) {
        $groups += $policyItem.AzureDevOps
    }

    foreach ($group in $groups) {

        if (-not $securityDescriptors.ContainsKey($group)) {
            Write-Host ">> Unrecognized group: $group (skipping)"
            continue
        }

        $descriptorItem = @{
            Type       = "Group"
            Name       = $group
            Descriptor = $securityDescriptors[$group]
        }
        $descriptors += , $descriptorItem
    }
    return $descriptors
}

function Set-BranchSecurityPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrganizationUrl,
        [Parameter(Mandatory = $true)]
        [object]$PolicyItem,
        [Parameter(Mandatory = $true)]
        [object]$Descriptors,
        [Parameter(Mandatory = $true)]
        [object]$Repositories,
        [Parameter(Mandatory = $true)]
        [object]$Namespace
    )

    Write-Host ("Policy: {0}" -f $policyItem.Name)
    Write-Host ("`t- Allow: {0}, Deny {1}" -f $policyItem.AllowBit, $policyItem.DenyBit)

    foreach ($descriptorItem in $Descriptors) {
        # show group: names
        Write-Host ("`t- {0}: {1}" -f $descriptorItem.Type, $descriptorItem.Name)

        $projectId = $Repositories[0].project.id
        $securityDescriptor = $descriptorItem.Descriptor
        foreach ($repo in $Repositories) {
            Write-Host ("`t- Repository: {0}" -f $repo.name)

            $repositoryId = $repo.id

            if ($null -eq $policyItem.Branches) {

                Write-Host "`t`t- Policy Kind: Repository" -NoNewline

                # apply policy to repository
                Set-BranchSecurity `
                    -OrganizationUrl $OrganizationUrl `
                    -Policy $policyItem `
                    -ProjectId $projectId `
                    -RepositoryId $repositoryId `
                    -SecurityDescriptor $securityDescriptor `
                    -Namespace $Namespace
            }
            else {

                Write-Host "`t`t- Policy Kind: Branch"

                foreach ($branch in $policyItem.Branches) {
                    Write-Host "`t`t`t- Branch: $branch" -NoNewline

                    Set-BranchSecurity `
                        -OrganizationUrl $OrganizationUrl `
                        -Policy $policyItem `
                        -ProjectId $projectId `
                        -RepositoryId $repositoryId `
                        -Branch $branch `
                        -SecurityDescriptor $securityDescriptor `
                        -Namespace $Namespace
                }
            }
        }
    }
}

#
# MAIN
#

Write-Host "Branch Security: $ProjectName"
Write-Host "-----------------------------------"
Write-Host "Getting things ready...."

Write-Host "`t...fetching security namespace"
$namespace = Get-SecurityNamespace -OrganizationUrl $OrganizationUrl -NamespaceName 'Git Repositories'

Write-Host "`t...descriptors for user groups"
$securityDescriptors = Get-SecurityDescriptorsLookupTable -OrganizationUrl $OrganizationUrl -ProjectName $ProjectName

# Add Azure DevOps default service users
# E.g. Project Collection Build Service (cmhcvsts)
$organizationName = $OrganizationUrl.TrimEnd("/").Split("/")[-1]
Get-AzGraphUsers -OrganizationName $organizationName -AccessToken $AccessToken -SubjectTypes @('svc') | ForEach-Object {
    if (-not $securityDescriptors.ContainsKey($_.displayName)) {
        $securityDescriptors.Add($_.displayName, $_.descriptor)
    }
}

Write-Host "`t...loading desired security policy"
$policies = $SecurityPolicyDefinition
if ($null -eq $policies) {
    $policies = Get-BranchSecurityPolicyDefinition
}

Write-Host ("`t...list of repositories")
$projectRepositories = Invoke-AzCli "repos list --project '$ProjectName' --organization '$OrganizationUrl'"

if ($RepositoryName) {
    $projectRepositories = $projectRepositories | Where-Object { $_.name -eq $RepositoryName }
}
else {
    $projectRepositories = $projectRepositories | Where-Object { -not ($_.name -in $RepositoryExclusion) }
}

Write-Host

#
# APPLY SECURITY POLICY
#

Write-Host "Applying branch security policies to: " $ProjectName

$policies | ForEach-Object {

    $descriptors = Resolve-SecurityDescriptorsFromPolicy -ProjectName $ProjectName -PolicyItem $_ -SecurityDescriptors $securityDescriptors
    if ($descriptors.Length -eq 0) {
        Write-Host "Policy does not apply to any known users or groups. (skipping)"
        continue
    }

    Set-BranchSecurityPolicy `
        -OrganizationUrl $OrganizationUrl `
        -PolicyItem $_ `
        -Descriptors $descriptors `
        -Repositories $projectRepositories `
        -Namespace $namespace
}

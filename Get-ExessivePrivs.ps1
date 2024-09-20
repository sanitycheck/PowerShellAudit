$excessivePermissions = @(
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "AllExtendedRights",
    "ExtendedRight"
)

# Function to retrieve ACLs and check for excessive permissions on AD objects
function Get-ExcessivePrivileges {
    $usersWithExcessivePrivs = @()

    # Get all user objects from Active Directory
    $allUsers = Get-ADUser -Filter * -Property SamAccountName, DistinguishedName

    foreach ($user in $allUsers) {
        try {
            # Get the ACL (Access Control List) for the user object
            $acl = Get-ACL -Path ("AD:\" + $user.DistinguishedName)

            # Loop through each access rule in the ACL
            foreach ($access in $acl.Access) {
                # Check if the access rule contains any of the excessive permissions
                foreach ($perm in $excessivePermissions) {
                    if ($access.ActiveDirectoryRights.ToString() -contains $perm) {
                        $excessivePrivEntry = [pscustomobject]@{
                            UserName = $user.SamAccountName
                            DistinguishedName = $user.DistinguishedName
                            ExcessivePermission = $perm
                            IdentityReference = $access.IdentityReference
                            AccessControlType = $access.AccessControlType
                        }
                        $usersWithExcessivePrivs += $excessivePrivEntry
                    }
                }
            }
        } catch {
            Write-Warning "Failed to retrieve ACL for user $($user.SamAccountName). Error: $_"
        }
    }

    # Output the results
    if ($usersWithExcessivePrivs.Count -gt 0) {
        $usersWithExcessivePrivs | Format-Table -AutoSize
    } else {
        Write-Host "No users found with excessive privileges."
    }
}

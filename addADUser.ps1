clear

# ������� ��� �������������� ��������� � ��������
function Convert-ToTranslit {
    param([string]$inString)

    $Translit_To_LAT = @{
        [char]'�' = "a"; [char]'�' = "a"
        [char]'�' = "b"; [char]'�' = "b"
        [char]'�' = "v"; [char]'�' = "v"
        [char]'�' = "g"; [char]'�' = "g"
        [char]'�' = "d"; [char]'�' = "d"
        [char]'�' = "e"; [char]'�' = "e"
        [char]'�' = "e"; [char]'�' = "e"
        [char]'�' = "zh"; [char]'�' = "zh"
        [char]'�' = "z"; [char]'�' = "z"
        [char]'�' = "i"; [char]'�' = "i"
        [char]'�' = "j"; [char]'�' = "j"
        [char]'�' = "k"; [char]'�' = "k"
        [char]'�' = "l"; [char]'�' = "l"
        [char]'�' = "m"; [char]'�' = "m"
        [char]'�' = "n"; [char]'�' = "n"
        [char]'�' = "o"; [char]'�' = "o"
        [char]'�' = "p"; [char]'�' = "p"
        [char]'�' = "r"; [char]'�' = "r"
        [char]'�' = "s"; [char]'�' = "s"
        [char]'�' = "t"; [char]'�' = "t"
        [char]'�' = "u"; [char]'�' = "u"
        [char]'�' = "f"; [char]'�' = "f"
        [char]'�' = "kh"; [char]'�' = "kh"
        [char]'�' = "tc"; [char]'�' = "tc"
        [char]'�' = "ch"; [char]'�' = "ch"
        [char]'�' = "sh"; [char]'�' = "sh"
        [char]'�' = "shch"; [char]'�' = "shch"
        [char]'�' = ""; [char]'�' = ""
        [char]'�' = "y"; [char]'�' = "y"
        [char]'�' = ""; [char]'�' = ""
        [char]'�' = "e"; [char]'�' = "e"
        [char]'�' = "yu"; [char]'�' = "yu"
        [char]'�' = "ia"; [char]'�' = "ia"
        [char]' ' = "_"
    }

    $outChars = ""

    foreach ($c in $inString.ToLower().ToCharArray()) {
        if ($Translit_To_LAT[$c] -ne $null) {
            $outChars += $Translit_To_LAT[$c]
        } else {
            $outChars += $c
        }
    }

    return $outChars
}

# ��������� ������
function Generate-Username {
    param (
        [string]$firstName,
        [string]$lastName
    )

    $firstNameTranslit = Convert-ToTranslit $firstName
    $lastNameTranslit = Convert-ToTranslit $lastName

    # �������� �� ������� ����� ���������
    if ([string]::IsNullOrWhiteSpace($firstNameTranslit) -or [string]::IsNullOrWhiteSpace($lastNameTranslit)) {
        Write-Host "`n������`t`t`t: ��� ��� ������� �� ����� ���� ������� ����� ���������."
        exit
    }

    $baseUsername = "$([char]($firstNameTranslit.Substring(0,1))).$($lastNameTranslit.ToLower())"
    $username = $baseUsername

    # �������� ������������ �������
    $counter = 1
    while (Get-ADUser -Filter { SamAccountName -eq $username -or Name -eq "$lastName $firstName" }) {
        # ���� �� ����� �� ������������ ����� �����, ��������� ������
        if ($counter -ge $firstNameTranslit.Length) {
            $username = "$firstNameTranslit.$($lastNameTranslit.ToLower())$counter"
        } else {
            # ����������� ����� ����� ��� ��������� ������ ������
            $firstNamePart = $firstNameTranslit.Substring(0, [math]::Min($counter + 1, $firstNameTranslit.Length))
            $username = "$firstNamePart.$($lastNameTranslit.ToLower())"
        }
        $counter++
    }

    return $username
}

# ������� �������� ������ �� �������������
function Check-UsernameExists {
    param (
        [string]$username
    )
    return Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue
}

# ���� ������� � ����� ����� �������
$lastName = Read-Host  "������� ������� "
$firstName = Read-Host "������� ���     "

# �������� ������
$username = Generate-Username -firstName $firstName -lastName $lastName

# ������ ������ �������
#$manualUsername = Read-Host "`n����� (��-��������� $username)`t"
#if (-not [string]::IsNullOrWhiteSpace($manualUsername)) {
#    $username = $manualUsername
#}

# ������ ������ ������� � ��������� �������������
$manualUsername = $null
$logonIsValid = $false

do {
    # ����������� ������ ����� �������
    $manualUsername = Read-Host "`n����� (��-��������� $username)"

    # ���� ������������ ������ ����� �������
    if (-not [string]::IsNullOrWhiteSpace($manualUsername)) {
        if (Check-UsernameExists -username $manualUsername) {
            Write-Host "`n������          : ����� $manualUsername ��� ����������. ���������� ������."
        } else {
            $username = $manualUsername
            $logonIsValid = $true
        }
    }

    # ���� ������������ ��������� ���� ������, ��������� ��������������� �����
    if ([string]::IsNullOrWhiteSpace($manualUsername)) {
        if (Check-UsernameExists -username $username) {
            Write-Host "`n������          : ����� $username ��� ����������."
            $username = Generate-Username -firstName $firstName -lastName $lastName # ��������� ������ ����������� ������
        } else {
            $logonIsValid = $true
        }
    }

} while (-not $logonIsValid)

# ��������� ����������� �����
function Generate-UniqueName {
    param (
        [string]$firstName,
        [string]$lastName
    )

    $name = "$lastName $firstName"
    $counter = 1

    while (Get-ADUser -Filter { Name -eq $name }) {
        # ����������� ������ ��� �������� ����������� �����
        $name = "$lastName $firstName $counter"
        $counter++
    }

    return $name
}

# ��������� ����������� �����
$uniqueName = Generate-UniqueName -firstName $firstName -lastName $lastName

# ��������� ������ � ������ ����������
function Generate-Password {
    $length = 8 # Set the desired password length
    $allowedChars = "ABCDEFGHKLMNPRSTUVXYZabcdefghkmnprstuvxyz23456789"
    
    # Convert string to an array of characters and select random characters from it
    $password = -join ((1..$length) | ForEach-Object { $allowedChars.ToCharArray() | Get-Random })
    
    return $password
}

# ��������� ������
$password = Generate-Password

# ���� ������ ������� � ��������� �����
$manualPassword = $null
do {
    $manualPassword = Read-Host "`n������ (��-��������� $password)"`
    
    # ���� ������������ ������ �� ����, ���������� ������ �� ���������
    if ([string]::IsNullOrWhiteSpace($manualPassword)) {
        $manualPassword = $password
    }
    
    # ��������� ����� ������
    if ($manualPassword.Length -lt 6) {
        Write-Host "`n������: ������ ������ ��������� ������� 6 ��������. ���������� �����."
    }
} while ($manualPassword.Length -lt 6)

# ������������� ������, ������� ������ ��������
$password = $manualPassword

# ���� � OU
$ouPath = "OU=Users (manual),OU=BAVARIA,DC=BAV,DC=LOCAL"

# �������� ������� ������ � Active Directory
$newUser = New-ADUser -Name $uniqueName `
           -GivenName $firstName `
           -Surname $lastName `
           -SamAccountName $username `
           -UserPrincipalName "$username@bavaria-group.ru" `
           -EmailAddress "$username@bavaria-group.ru" `
           -DisplayName $uniqueName `
           -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
           -Enabled $true `
           -Path $ouPath -PassThru `
           -PasswordNeverExpires $true `  # ������ ������� �� ��������

# �������� �� �������� ������������
if ($newUser -ne $null) {
    # ��������� ����� ������ �������������
    Set-ADUser -Identity $newUser.SamAccountName -CannotChangePassword $true

    # ���������� � ������
    Add-ADGroupMember -Identity "������ ������" -Members $newUser.SamAccountName
    Add-ADGroupMember -Identity '$V41000-3RQ8RNT3HMTF' -Members $newUser.SamAccountName
    #Write-Host "������������ ������� �������� � ������."
} else {
    Write-Host "������          : ������������ �� ��� ������."
}

#��������� � ����� ������
Set-Clipboard -Value "������������: $uniqueName`n�����: $($username)@bavaria-group.ru`n������: $password"

#���������� � ���� PassWork
Write-Host "`n-------------------------------------------------------------`n"
Write-Host "Passwork - ���������� � ����:"
. "${PSScriptRoot}\passwork_lib.ps1"
#$passwork = [Passwork]::new("https://passwork.bavaria-group.ru/api/v4")
$passwork = [Passwork]::new("http://172.20.0.253/api/v4")
$auth = $passwork.login("9mEubTheqzrgLUpAAUGTiqViNDkuVfT7APjPKefgxPoGkbICGARFHo6UbJk6")
if ($auth){
    $vault = $passwork.searchVault("AD")
    if ($vault -ne $null){
        $passwork.AddPassword(
            @{
                vaultId = $vault.id 
                name = "$uniqueName"
                login = "$username"
                cryptedPassword = "$password"
                custom = @(
                    @{
                        name  = "�����"
                        value = "$username@bavaria-group.ru"
                        type  = "text"
                    }
                )
                color = 4 
                tags = @("$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
            })   
    }
    $passwork.logout()
}

# ����� ������ � ������
Write-Host "`n-------------------------------------------------------------`n"
Write-Host "������������: $uniqueName"
Write-Host "�����:        $($username)@bavaria-group.ru"
Write-Host "������:       $password"
Write-Host ""

pause
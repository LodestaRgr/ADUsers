clear

# Функция для преобразования кириллицы в транслит
function Convert-ToTranslit {
    param([string]$inString)

    $Translit_To_LAT = @{
        [char]'а' = "a"; [char]'А' = "a"
        [char]'б' = "b"; [char]'Б' = "b"
        [char]'в' = "v"; [char]'В' = "v"
        [char]'г' = "g"; [char]'Г' = "g"
        [char]'д' = "d"; [char]'Д' = "d"
        [char]'е' = "e"; [char]'Е' = "e"
        [char]'ё' = "e"; [char]'Ё' = "e"
        [char]'ж' = "zh"; [char]'Ж' = "zh"
        [char]'з' = "z"; [char]'З' = "z"
        [char]'и' = "i"; [char]'И' = "i"
        [char]'й' = "j"; [char]'Й' = "j"
        [char]'к' = "k"; [char]'К' = "k"
        [char]'л' = "l"; [char]'Л' = "l"
        [char]'м' = "m"; [char]'М' = "m"
        [char]'н' = "n"; [char]'Н' = "n"
        [char]'о' = "o"; [char]'О' = "o"
        [char]'п' = "p"; [char]'П' = "p"
        [char]'р' = "r"; [char]'Р' = "r"
        [char]'с' = "s"; [char]'С' = "s"
        [char]'т' = "t"; [char]'Т' = "t"
        [char]'у' = "u"; [char]'У' = "u"
        [char]'ф' = "f"; [char]'Ф' = "f"
        [char]'х' = "kh"; [char]'Х' = "kh"
        [char]'ц' = "tc"; [char]'Ц' = "tc"
        [char]'ч' = "ch"; [char]'Ч' = "ch"
        [char]'ш' = "sh"; [char]'Ш' = "sh"
        [char]'щ' = "shch"; [char]'Щ' = "shch"
        [char]'ъ' = ""; [char]'Ъ' = ""
        [char]'ы' = "y"; [char]'Ы' = "y"
        [char]'ь' = ""; [char]'Ь' = ""
        [char]'э' = "e"; [char]'Э' = "e"
        [char]'ю' = "yu"; [char]'Ю' = "yu"
        [char]'я' = "ia"; [char]'Я' = "ia"
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

# Генерация логина
function Generate-Username {
    param (
        [string]$firstName,
        [string]$lastName
    )

    $firstNameTranslit = Convert-ToTranslit $firstName
    $lastNameTranslit = Convert-ToTranslit $lastName

    # Проверка на пустоту после транслита
    if ([string]::IsNullOrWhiteSpace($firstNameTranslit) -or [string]::IsNullOrWhiteSpace($lastNameTranslit)) {
        Write-Host "`nОшибка`t`t`t: имя или фамилия не могут быть пустыми после транслита."
        exit
    }

    $baseUsername = "$([char]($firstNameTranslit.Substring(0,1))).$($lastNameTranslit.ToLower())"
    $username = $baseUsername

    # Проверка существующих логинов
    $counter = 1
    while (Get-ADUser -Filter { SamAccountName -eq $username -or Name -eq "$lastName $firstName" }) {
        # Если мы дошли до максимальной длины имени, добавляем индекс
        if ($counter -ge $firstNameTranslit.Length) {
            $username = "$firstNameTranslit.$($lastNameTranslit.ToLower())$counter"
        } else {
            # Увеличиваем длину имени для генерации нового логина
            $firstNamePart = $firstNameTranslit.Substring(0, [math]::Min($counter + 1, $firstNameTranslit.Length))
            $username = "$firstNamePart.$($lastNameTranslit.ToLower())"
        }
        $counter++
    }

    return $username
}

# Функция проверки логина на существование
function Check-UsernameExists {
    param (
        [string]$username
    )
    return Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue
}

# Ввод фамилии и имени через консоль
$lastName = Read-Host  "Введите Фамилию "
$firstName = Read-Host "Введите Имя     "

# Создание логина
$username = Generate-Username -firstName $firstName -lastName $lastName

# Запрос логина вручную
#$manualUsername = Read-Host "`nЛогин (по-умолчанию $username)`t"
#if (-not [string]::IsNullOrWhiteSpace($manualUsername)) {
#    $username = $manualUsername
#}

# Запрос логина вручную с проверкой существования
$manualUsername = $null
$logonIsValid = $false

do {
    # Предложение ввести логин вручную
    $manualUsername = Read-Host "`nЛогин (по-умолчанию $username)"

    # Если пользователь вводит логин вручную
    if (-not [string]::IsNullOrWhiteSpace($manualUsername)) {
        if (Check-UsernameExists -username $manualUsername) {
            Write-Host "`nОшибка          : логин $manualUsername уже существует. Попробуйте другой."
        } else {
            $username = $manualUsername
            $logonIsValid = $true
        }
    }

    # Если пользователь оставляет поле пустым, проверяем сгенерированный логин
    if ([string]::IsNullOrWhiteSpace($manualUsername)) {
        if (Check-UsernameExists -username $username) {
            Write-Host "`nОшибка          : логин $username уже существует."
            $username = Generate-Username -firstName $firstName -lastName $lastName # Генерация нового уникального логина
        } else {
            $logonIsValid = $true
        }
    }

} while (-not $logonIsValid)

# Генерация уникального имени
function Generate-UniqueName {
    param (
        [string]$firstName,
        [string]$lastName
    )

    $name = "$lastName $firstName"
    $counter = 1

    while (Get-ADUser -Filter { Name -eq $name }) {
        # Увеличиваем индекс для создания уникального имени
        $name = "$lastName $firstName $counter"
        $counter++
    }

    return $name
}

# Генерация уникального имени
$uniqueName = Generate-UniqueName -firstName $firstName -lastName $lastName

# Генерация пароля с учетом требований
function Generate-Password {
    $length = 8 # Set the desired password length
    $allowedChars = "ABCDEFGHKLMNPRSTUVXYZabcdefghkmnprstuvxyz23456789"
    
    # Convert string to an array of characters and select random characters from it
    $password = -join ((1..$length) | ForEach-Object { $allowedChars.ToCharArray() | Get-Random })
    
    return $password
}

# Генерация пароля
$password = Generate-Password

# Ввод пароля вручную с проверкой длины
$manualPassword = $null
do {
    $manualPassword = Read-Host "`nПароль (по-умолчанию $password)"`
    
    # Если пользователь ничего не ввел, используем пароль по умолчанию
    if ([string]::IsNullOrWhiteSpace($manualPassword)) {
        $manualPassword = $password
    }
    
    # Проверяем длину пароля
    if ($manualPassword.Length -lt 6) {
        Write-Host "`nОшибка: Пароль должен содержать минимум 6 символов. Попробуйте снова."
    }
} while ($manualPassword.Length -lt 6)

# Устанавливаем пароль, который прошел проверку
$password = $manualPassword

# Путь к OU
$ouPath = "OU=Users (manual),OU=BAVARIA,DC=BAV,DC=LOCAL"

# Создание учетной записи в Active Directory
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
           -PasswordNeverExpires $true `  # Пароль никогда не истекает

# Проверка на создание пользователя
if ($newUser -ne $null) {
    # Запретить смену пароля пользователем
    Set-ADUser -Identity $newUser.SamAccountName -CannotChangePassword $true

    # Добавление в группу
    Add-ADGroupMember -Identity "Старый сервер" -Members $newUser.SamAccountName
    Add-ADGroupMember -Identity '$V41000-3RQ8RNT3HMTF' -Members $newUser.SamAccountName
    #Write-Host "Пользователь успешно добавлен в группу."
} else {
    Write-Host "Ошибка          : пользователь не был создан."
}

#Сохранить в буфер обмена
Set-Clipboard -Value "Пользователь: $uniqueName`nЛогин: $($username)@bavaria-group.ru`nПароль: $password"

#Добавление в базу PassWork
Write-Host "`n-------------------------------------------------------------`n"
Write-Host "Passwork - сохранение в базу:"
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
                        name  = "Почта"
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

# Вывод логина и пароля
Write-Host "`n-------------------------------------------------------------`n"
Write-Host "Пользователь: $uniqueName"
Write-Host "Логин:        $($username)@bavaria-group.ru"
Write-Host "Пароль:       $password"
Write-Host ""

pause
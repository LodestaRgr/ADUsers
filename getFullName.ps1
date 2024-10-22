#
#Set-ExecutionPolicy RemoteSigned
#Install-Module -Name ActiveDirectory -Force -AllowClobber

# Импорт модуля Active Directory
Import-Module ActiveDirectory

# Получение sAMAccountName текущего пользователя
$currentUserName = $env:USERNAME


# Получение информации о пользователе
$user = Get-ADUser -Filter "SamAccountName -eq '$currentUserName'" -Properties DisplayName

# Вывод полного имени пользователя
if ($user -ne $null) {
    Write-Host "Полное имя пользователя: $($user.DisplayName)"
} else {
    Write-Host "Пользователь не найден в Active Directory."
}
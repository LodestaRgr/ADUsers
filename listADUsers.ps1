clear
Add-Type -AssemblyName System.Windows.Forms
$upn = "@bavaria-group.ru"
$font = New-Object System.Drawing.Font("Lucida Console", 10, [System.Drawing.FontStyle]::Regular)

# Создаем форму
$form = New-Object System.Windows.Forms.Form
$form.Text = "Управление пользователями AD"
$form.Size = New-Object System.Drawing.Size(700, 800)

# Создаем ListBox для отображения пользователей
$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Dock = 'Fill'
$listBox.Font = $font
$form.Controls.Add($listBox)

# Создаем текстовое поле для поиска
$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Dock = 'Top'
$searchBox.Font = $font
$form.Controls.Add($searchBox)

# Глобальный кэш для пользователей
$global:userCache = @()

# Заполняем ListBox данными пользователей из указанного OU
$ouPath = "OU=Users (manual),OU=BAVARIA,DC=BAV,DC=LOCAL"

# Функция для обновления списка пользователей в кэше
function Update-UserCache {
    $global:userCache = Get-ADUser -Filter * -SearchBase $ouPath -Properties whenChanged, Enabled | Select-Object Name, SamAccountName, whenChanged, Enabled
}

# Имя RDS сервера и коллекции
$rdsServerName = "SR-RDS1.bav.local"
$collectionName = "SS"

#$showDisabledUsersMenuItem.Checked = $false

# Функция для обновления списка пользователей в ListBox
function Update-UserList {
    $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties whenChanged, Enabled | Select-Object Name, SamAccountName, whenChanged, Enabled

    $listBox.Items.Clear()
    
    # Фильтрация пользователей по тексту поиска
    $filteredUsers = $users | Where-Object { 
        ($_.Name -like "*$($searchBox.Text)*") -or 
        ($_.SamAccountName -like "*$($searchBox.Text)*")
    }

    # Если опция "Показывать отключенных пользователей" не выбрана, скрываем отключенных пользователей
    if (-not $showDisabledUsersMenuItem.Checked) {
        $filteredUsers = $filteredUsers | Where-Object { $_.Enabled -eq $true }
    }

    $global:sortedUsers = $filteredUsers | Sort-Object Name
    # Получаем информацию о сеансах RDS
    #$sessionInfo = Get-RDUserSession -ConnectionBroker $rdsServerName -CollectionName $collectionName | Select-Object UserName, SessionState

    foreach ($user in $global:sortedUsers) {
        $status = if ($user.Enabled) { "Включен " } else { "Отключен" }
        # Получаем состояние сеанса для текущего пользователя
        #$sessionStatus = $sessionInfo | Where-Object { $_.UserName -eq $user.SamAccountName }
        
        # Определяем состояние подключения
        #if ($sessionStatus) {
        #    switch ($sessionStatus.SessionState) {
        #        "STATE_ACTIVE" { $sessionState = "Активный" }
        #        "STATE_CONNECTED" { $sessionState = "Активный" }
        #        "STATE_DISCONNECTED" { $sessionState = "Отключен" }
        #        default { $sessionState = "Отключен" } # Если состояние неизвестное, считаем отключенным
        #    }
        #} else {
        #    $sessionState = "Отключен" # Если пользователя нет в сеансах
        #}

        #$listBox.Items.Add("$($user.Name.PadRight(30).Substring(0,30)) | $($user.SamAccountName.PadRight(15).Substring(0,15)) | $status | $sessionState | $($user.whenChanged)")  | Out-Null
        $listBox.Items.Add("$($user.Name.PadRight(30).Substring(0,30)) | $($user.SamAccountName.PadRight(15).Substring(0,15)) | $status | $($user.whenChanged)") | Out-Null
    }
}

# Заполняем ListBox изначально
Update-UserList
# Обработчик для изменения текста в поисковом поле
$searchBox.Add_TextChanged({
    Update-UserList
})

# Создаем контекстное меню
$contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

# Создание основного элемента меню
$mainMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$mainMenuItem.Text = "Редактировать ..."

# Сменить пароль
$changePasswordMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$changePasswordMenuItem.Text = "Смена пароля"
$changePasswordMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]

        # Создаем форму для ввода пароля
        $passwordForm = New-Object System.Windows.Forms.Form
        $passwordForm.Text = "Сменить пароль $($selectedUser.SamAccountName)"
        $passwordForm.Size = New-Object System.Drawing.Size(390, 90)

        # Новое поле пароля
        $newPasswordBox = New-Object System.Windows.Forms.TextBox
        $newPasswordBox.Location = New-Object System.Drawing.Point(15, 15)
        $newPasswordBox.Size = New-Object System.Drawing.Size(250, 20)
        $newPasswordBox.UseSystemPasswordChar = $false
        $passwordForm.Controls.Add($newPasswordBox)

        # Кнопка подтверждения
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(280, 14)
        $okButton.Size = New-Object System.Drawing.Size(75, 23)
        $okButton.Text = "Сменить"
        $okButton.Add_Click({
            $newPassword = $newPasswordBox.Text

            try {
                # Смена пароля
                Set-ADAccountPassword $selectedUser.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force -Verbose) –PassThru
                [System.Windows.Forms.MessageBox]::Show("Пользователь: $($selectedUser.Name)`nЛогин: $($selectedUser.SamAccountName)$upn`nПароль: $newPassword", "Пароль изменен")

                #Сохранить в буфер обмена
                Set-Clipboard -Value "Пользователь: $($selectedUser.Name)`nЛогин: $($selectedUser.SamAccountName)$upn`nПароль: $newPassword"

                Update-UserList
                $passwordForm.Close()
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Ошибка: $_", "Ошибка")
            }
        })
        $passwordForm.Controls.Add($okButton)

        # Отображаем форму для ввода пароля
        $passwordForm.ShowDialog()
    }
})
$mainMenuItem.DropDownItems.Add($changePasswordMenuItem) | Out-Null

# Сменить логин
$renameMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$renameMenuItem.Text = "Сменить логин"
$renameMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]

        # Создаем форму для ввода
        $newLoginForm = New-Object System.Windows.Forms.Form
        $newLoginForm.Text = "Сменить логин $($selectedUser.SamAccountName)"
        $newLoginForm.Size = New-Object System.Drawing.Size(390, 90)

        # Новое поле 
        $newLoginBox = New-Object System.Windows.Forms.TextBox
        $newLoginBox.Location = New-Object System.Drawing.Point(15, 15)
        $newLoginBox.Size = New-Object System.Drawing.Size(250, 20)
        $newLoginBox.Text = $selectedUser.SamAccountName
        $newLoginForm.Controls.Add($newLoginBox)

        # Кнопка подтверждения
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(280, 14)
        $okButton.Size = New-Object System.Drawing.Size(75, 23)
        $okButton.Text = "Сменить"
        $okButton.Add_Click({
            $newLogin = $newLoginBox.Text

            try {
                # Смена логина
                $user = Get-ADUser -Identity $selectedUser.SamAccountName
                Set-ADUser -Identity $user -SamAccountName $newLogin
                Set-ADUser -Identity $user -UserPrincipalName $newLogin$upn

                [System.Windows.Forms.MessageBox]::Show("Пользователь - $($selectedUser.SamAccountName)$upn`nпереименован - $newLogin$upn", "Сменен")

                $newLoginForm.Close()
                Update-UserList
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Ошибка: $_", "Ошибка")
            }
        })
        $newLoginForm.Controls.Add($okButton)

        # Отображаем форму для ввода
        $newLoginForm.ShowDialog()
    }
})

$mainMenuItem.DropDownItems.Add($renameMenuItem) | Out-Null

# Переименовать
$renameMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$renameMenuItem.Text = "Переименовать"
$renameMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]

        # Создаем форму для ввода
        $newNameForm = New-Object System.Windows.Forms.Form
        $newNameForm.Text = "Переименовать $($selectedUser.Name)"
        $newNameForm.Size = New-Object System.Drawing.Size(390, 90)

        # Новое поле 
        $newNameBox = New-Object System.Windows.Forms.TextBox
        $newNameBox.Location = New-Object System.Drawing.Point(15, 15)
        $newNameBox.Size = New-Object System.Drawing.Size(250, 20)
        $newNameBox.Text = $selectedUser.Name
        $newNameForm.Controls.Add($newNameBox)

        # Кнопка подтверждения
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(280, 14)
        $okButton.Size = New-Object System.Drawing.Size(75, 23)
        $okButton.Text = "Сменить"
        $okButton.Add_Click({
            $newName = $newNameBox.Text

            try {

                # Смена имени
                $user = Get-ADUser -Identity $selectedUser.SamAccountName

                #Разделяем полное имя на фамилия и имя
                if ($newName -like "* *") {
                    # Разделяем строку на части
                    $nameParts = $newName -split ' '

                    # Проверяем, есть ли достаточно частей
                    if ($nameParts.Length -ge 2) {
                        # Устанавливаем значения для GivenName и Surname
                        Set-ADUser -Identity $user -DisplayName $newName -GivenName $nameParts[1] -SurName $nameParts[0] -PassThru |
                        Rename-ADObject -NewName $newName

                    } else {
                        #Недостаточно значений для разделения
                        Set-ADUser -Identity $user -DisplayName $newName -PassThru |
                        Rename-ADObject -NewName $newName
                    }
                } else {
                    #В строке нет пробелов, ничего не делаем.
                    Set-ADUser -Identity $user -DisplayName $newName -PassThru |
                    Rename-ADObject -NewName $newName
                }


                # Проверяем, содержит ли строка пробел
                [System.Windows.Forms.MessageBox]::Show("Пользователь - $($selectedUser.Name)`nпереименован - $newName.", "Переименован")

                $newNameForm.Close()
                Update-UserList
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Ошибка: $_", "Ошибка")
            }
        })
        $newNameForm.Controls.Add($okButton)

        # Отображаем форму для ввода
        $newNameForm.ShowDialog()
    }
})
$mainMenuItem.DropDownItems.Add($renameMenuItem) | Out-Null

# Добавление основного элемента меню в контекстное меню
$contextMenu.Items.Add($mainMenuItem) | Out-Null

# Добавить меню для групп
$groupMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$groupMenuItem.Text = "Добавить в группу ..."
$groupMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]

        # Получаем все группы из OU
        $allGroups = Get-ADGroup -Filter * -SearchBase "OU=Доступ,OU=Groups,OU=BAVARIA,DC=BAV,DC=LOCAL"

        # Получаем группы, в которых состоит пользователь
        $userGroups = (Get-ADUser -Identity $selectedUser.SamAccountName -Properties MemberOf).MemberOf

        # Создаем форму для отображения групп
        $groupForm = New-Object System.Windows.Forms.Form
        $groupForm.Text = "Группы пользователя: $($selectedUser.Name)"
        $groupForm.Size = New-Object System.Drawing.Size(400, 300)

        # Создаем GroupBox для групп
        $groupBox = New-Object System.Windows.Forms.GroupBox
        $groupBox.Text = "Список групп"
        $groupBox.Dock = 'Fill'
        $groupForm.Controls.Add($groupBox)

        # Создаем ListBox для отображения групп
        $groupListBox = New-Object System.Windows.Forms.ListBox
        $groupListBox.Dock = 'Fill'
        $groupListBox.SelectionMode = 'MultiSimple' # Разрешаем множественный выбор
        $groupBox.Controls.Add($groupListBox)

        # Заполняем ListBox группами
        foreach ($group in $allGroups) {
            $groupListBox.Items.Add($group.Name)

            # Проверяем, состоит ли пользователь в этой группе
            if ($userGroups -contains $group.DistinguishedName) {
                # Находим индекс группы в ListBox и выделяем ее
                $index = $groupListBox.Items.IndexOf($group.Name)
                $groupListBox.SetSelected($index, $true)
            }
        }

        # Создаем кнопку "Применить"
        $applyButton = New-Object System.Windows.Forms.Button
        $applyButton.Text = "Применить"
        $applyButton.Dock = 'Bottom'
        $applyButton.Add_Click({
            foreach ($group in $allGroups) {
                $groupName = $group.Name
                $groupDN = $group.DistinguishedName
                $isSelected = $groupListBox.SelectedItems.Contains($groupName)

                try {
                    # Проверяем, должна ли группа содержать пользователя
                    if ($isSelected -and -not ($userGroups -contains $groupDN)) {
                        # Если группа выделена и пользователь не состоит в ней, добавляем пользователя
                        Add-ADGroupMember -Identity $group -Members $selectedUser.SamAccountName -ErrorAction Stop
                    } elseif (-not $isSelected -and ($userGroups -contains $groupDN)) {
                        # Если группа не выделена и пользователь состоит в ней, удаляем пользователя
                        Remove-ADGroupMember -Identity $group -Members $selectedUser.SamAccountName -Confirm:$false -ErrorAction Stop
                    }
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Ошибка при обновлении группы ${groupName}: $_", "Ошибка")
                }
            }

            # Закрыть форму после завершения процесса
            $groupForm.Close()
        })
        $groupForm.Controls.Add($applyButton)

        # Показываем форму групп
        $groupForm.ShowDialog()
    }
})
$contextMenu.Items.Add($groupMenuItem) | Out-Null

# Добавить разделитель
$separator = New-Object System.Windows.Forms.ToolStripSeparator
$contextMenu.Items.Add($separator) | Out-Null

# Добавить пользователя
$toggleAccountMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$toggleAccountMenuItem.Text = "Обновить"
$toggleAccountMenuItem.Add_Click({
    Update-UserList
})
$contextMenu.Items.Add($toggleAccountMenuItem) | Out-Null

# Добавить разделитель
$separator = New-Object System.Windows.Forms.ToolStripSeparator
$contextMenu.Items.Add($separator) | Out-Null

# Завершить сеанс
$endSessionMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$endSessionMenuItem.Text = "Завершить сеанс SSNew"
$endSessionMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]

        # Получаем состояние сеанса для текущего пользователя
        $sessionStatus = Get-RDUserSession -ConnectionBroker $rdsServerName -CollectionName $collectionName | Where-Object { $_.UserName -eq $selectedUser.SamAccountName }

        if ($sessionStatus) {
            $sessionState = $sessionStatus.SessionState
            if ($sessionState -eq "STATE_ACTIVE" -or $sessionState -eq "STATE_CONNECTED") {
                # Завершаем сеанс
                Invoke-RDUserLogoff -HostServer $sessionStatus.HostServer -UnifiedSessionID $sessionStatus.UnifiedSessionID -Force
                [System.Windows.Forms.MessageBox]::Show("Сеанс пользователя $($selectedUser.Name) завершен.", "Успех")
                Update-UserList
            } else {
                [System.Windows.Forms.MessageBox]::Show("Сеанс пользователя $($selectedUser.Name) не активен.", "Информация")
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Пользователь не подключен к сеансу.", "Информация")
        }
    }
})
$contextMenu.Items.Add($endSessionMenuItem) | Out-Null

# Просмотр сеанса (Теневая копия, только просмотр)
$viewSessionMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$viewSessionMenuItem.Text = "Просмотр сеанса ..."
$viewSessionMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]

        try {
            # Получаем состояние сеанса для текущего пользователя
            $sessionStatus = Get-RDUserSession -ConnectionBroker $rdsServerName -CollectionName $collectionName | Where-Object { $_.UserName -eq $selectedUser.SamAccountName }

            if ($sessionStatus) {
                # Получаем необходимые параметры для запуска теневой копии
                $hostServer = $sessionStatus.HostServer
                $sessionID = $sessionStatus.UnifiedSessionID

                # Запускаем mstsc для теневой копии сеанса в режиме только просмотра
                Start-Process mstsc.exe -ArgumentList "/shadow:$sessionID /v:$hostServer /noConsentPrompt"
            } else {
                # Если сеанс не найден
                [System.Windows.Forms.MessageBox]::Show("У пользователя $($selectedUser.Name) нет активных сеансов для просмотра.", "Информация о сеансе")
            }
        } catch {
            # В случае ошибки
            [System.Windows.Forms.MessageBox]::Show("Ошибка при попытке запуска теневой копии сеанса: $_", "Ошибка")
        }
    }
})
$contextMenu.Items.Add($viewSessionMenuItem) | Out-Null

# Управление сеансом
$viewSessionMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$viewSessionMenuItem.Text = "Управление сеансом ..."
$viewSessionMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]

        try {
            # Получаем состояние сеанса для текущего пользователя
            $sessionStatus = Get-RDUserSession -ConnectionBroker $rdsServerName -CollectionName $collectionName | Where-Object { $_.UserName -eq $selectedUser.SamAccountName }

            if ($sessionStatus) {
                # Получаем необходимые параметры для запуска теневой копии
                $hostServer = $sessionStatus.HostServer
                $sessionID = $sessionStatus.UnifiedSessionID

                # Запускаем mstsc для теневой копии сеанса
                Start-Process mstsc.exe -ArgumentList "/shadow:$sessionID /v:$hostServer /control /noConsentPrompt"
            } else {
                # Если сеанс не найден
                [System.Windows.Forms.MessageBox]::Show("У пользователя $($selectedUser.Name) нет активных сеансов для просмотра.", "Информация о сеансе")
            }
        } catch {
            # В случае ошибки
            [System.Windows.Forms.MessageBox]::Show("Ошибка при попытке запуска теневой копии сеанса: $_", "Ошибка")
        }
    }
})
$contextMenu.Items.Add($viewSessionMenuItem) | Out-Null

# Добавить разделитель
$separator = New-Object System.Windows.Forms.ToolStripSeparator
$contextMenu.Items.Add($separator) | Out-Null

# Добавить пункт "Показывать отключенных пользователей"
$showDisabledUsersMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$showDisabledUsersMenuItem.Text = "Показывать отключенных пользователей"
$showDisabledUsersMenuItem.CheckOnClick = $true # Галочка появляется при клике

# Добавляем обработчик клика по пункту меню
$showDisabledUsersMenuItem.Add_Click({
    Update-UserList
})
$contextMenu.Items.Add($showDisabledUsersMenuItem) | Out-Null

# Добавить разделитель
$separator = New-Object System.Windows.Forms.ToolStripSeparator
$contextMenu.Items.Add($separator) | Out-Null

# Добавить пользователя
$toggleAccountMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$toggleAccountMenuItem.Text = "Добавить пользователя ..."
$toggleAccountMenuItem.Add_Click({
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"\\bav.local\ss\scripts\private\addADUser.ps1`""
})
$contextMenu.Items.Add($toggleAccountMenuItem) | Out-Null

# Отключить/включить учетную запись
$toggleAccountMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$toggleAccountMenuItem.Text = "Отключить учетную запись"
$toggleAccountMenuItem.Image = [System.Drawing.SystemIcons]::Hand.ToBitmap()
$toggleAccountMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]
        if ($selectedUser.Enabled) {
            Disable-ADAccount -Identity $selectedUser.SamAccountName
            # Обновляем состояние пользователя в массиве
            $userToUpdate = $users | Where-Object { $_.SamAccountName -eq $selectedUser.SamAccountName }
            $userToUpdate.Enabled = $false
            #[System.Windows.Forms.MessageBox]::Show("Учетная запись $($selectedUser.Name) отключена.", "Успех")
        } else {
            Enable-ADAccount -Identity $selectedUser.SamAccountName
            # Обновляем состояние пользователя в массиве
            $userToUpdate = $users | Where-Object { $_.SamAccountName -eq $selectedUser.SamAccountName }
            $userToUpdate.Enabled = $true
            #[System.Windows.Forms.MessageBox]::Show("Учетная запись $($selectedUser.Name) включена.", "Успех")
        }
        Update-UserList
    }
})
$contextMenu.Items.Add($toggleAccountMenuItem) | Out-Null

# Добавить разделитель
$separator = New-Object System.Windows.Forms.ToolStripSeparator
$contextMenu.Items.Add($separator) | Out-Null

# Информация о пользователе
$toggleInfoMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$toggleInfoMenuItem.Text = "Информация о пользователе"
$toggleInfoMenuItem.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
$toggleInfoMenuItem.Add_Click({
    $selectedIndex = $listBox.SelectedIndex
    if ($selectedIndex -ge 0) {
        $selectedUser = $global:sortedUsers[$selectedIndex]

        $userPassword = "(нет данных)"

        #Сбор информации из базы PassWork
        Write-Host "`n-------------------------------------------------------------`n"
        Write-Host "Passwork - Сбор информации:"

        . "${PSScriptRoot}\passwork_lib.ps1"
        #$passwork = [Passwork]::new("https://passwork.bavaria-group.ru/api/v4")
        $passwork = [Passwork]::new("http://172.20.0.253/api/v4")
        $auth = $passwork.login("9mEubTheqzrgLUpAAUGTiqViNDkuVfT7APjPKefgxPoGkbICGARFHo6UbJk6")
        if ($auth){
            $vault = $passwork.searchVault("AD")
                if ($vault -ne $null){
                    Write-Host "Запрос: $($selectedUser.SamAccountName) $($selectedUser.Name)"
                    $response = $passwork.searchPassword(
                        @{
                            query = "$($selectedUser.SamAccountName) $($selectedUser.Name)"
                            #vaultId = $vault.id
                    })

                    if ($response.Count -ge 1) {
                        # Поиск нужного словаря
                        $result = $response | Where-Object { 
                            $_.name -eq "$($selectedUser.Name)" -and $_.login -like "*$($selectedUser.SamAccountName)*"
                        }
                        if ($result) {
                            $passd = $passwork.getPassword($result.id)
                            if ($passd -and $passd.cryptedPassword) {
                                $userPassword = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($passd.cryptedPassword))
                            }

                        }
                    }
                }
            $passwork.logout()
        }
        #Сохранить в буфер обмена
        Set-Clipboard -Value "Пользователь: $($selectedUser.Name)`nЛогин: $($selectedUser.SamAccountName)$upn`nПароль:  $userPassword"
        [System.Windows.Forms.MessageBox]::Show("Пользователь: $($selectedUser.Name)`nЛогин: $($selectedUser.SamAccountName)$upn`nПароль: $userPassword", "Информация о пользователе", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)


        Update-UserList
    }
})
$contextMenu.Items.Add($toggleInfoMenuItem) | Out-Null

# Привязываем контекстное меню к ListBox
$listBox.ContextMenuStrip = $contextMenu

# Показываем форму
$form.Add_Shown({$form.Activate()})
[void]$form.ShowDialog()
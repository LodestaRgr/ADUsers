class Passwork {
    [string]$baseurl
    [string]$apikey
    [string]$auth
    [object]$data

    Passwork([string]$baseurl) {
        $this.baseurl = $baseurl
    }

    [string]ConvertToUnicodeEscape([string]$inputString) {
        $escapedString = ""

        foreach ($char in $inputString.ToCharArray()) {
            $unicodeValue = [int][char]$char
            # If the character is outside of ASCII range, convert it to \uXXXX
            if ($unicodeValue -gt 127) {
                $escapedString += "\u" + "{0:x4}" -f $unicodeValue
            } else {
                $escapedString += $char
            }
        }

        return $escapedString
    }

    # Функция для конвертации в Base64 обратно в строку
    [string]ConvertToBase64([string]$inputString) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
        return [Convert]::ToBase64String($bytes)
    }

    # Функция для конвертации из Base64 обратно в строку
    [string]ConvertFromBase64([string]$base64String) {
        $bytes = [System.Convert]::FromBase64String($base64String)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }

    [object]SendRequest([string]$url, [string]$Method, $Body = $null) {
        $headers = @{
            "Accept" = "application/json"
            "Content-Type" = "application/json"
        }

        if ($this.data.token) {
            $headers["Passwork-Auth"] = $this.data.token
        }

        try {
            $response = Invoke-RestMethod -Uri "$($this.baseurl)$($url)" -Method $Method -Headers $headers -Body $Body
            return $response
        } catch {
            Write-Host "Ошибка запроса: $($_.Exception.Message)"
            return $null
        }
    }

    [bool]login([string]$apikey) {
        
        $this.apikey = $apikey

        $response = $this.SendRequest("/auth/login/$($this.apikey)", 'POST', $null)

        if ($response.status -eq 'success') {
            $this.data = $response.data
            Write-Host "Аутентификация успешна: $($this.data.user.name)"
            return $true
        } else {
            Write-Host "Ошибка аутентификации"
            return $false
        }
    }

    [void]logout() {
        $response = $this.SendRequest("/auth/logout", 'POST', $null)
        #Write-Host ($response | convertto-json)
        Write-Host "Завершение сеанса"
    }

    [object]getVault([string]$vaultId) {
       
        try {
            $response = $this.SendRequest("/vaults/$vaultId", 'GET', $null)
            return $response.data
        } catch {
            Write-Host "Ошибка запроса: $($_.Exception.Message)"
            return $null
        }
    }

    [object]getVaults() {
       
        try {
            $response = $this.SendRequest("/vaults/list", 'GET', $null)
            return $response
        } catch {
            Write-Host "Ошибка запроса: $($_.Exception.Message)"
            return $null
        }
    }

    [object]searchVault([string]$vaultname) {
       
        try {
            $vaults =  $this.getVaults()
            $response = $vaults.data | Where-Object { $_.name -eq $vaultname }
            
            if ($response -eq $null) {
                Write-Host "Сейф не найден"
                return $null
            }
                return $response
        } catch {
            Write-Host "Ошибка запроса: $($_.Exception.Message)"
            return $null
        }
    }

    [void]addFolder([string]$vaultId, [string]$folderName) {
        try {
            $body = @{
                "vaultId" = $vaultId
                "name" = $folderName
            } | ConvertTo-Json

            $response = $this.SendRequest("/folders", 'POST', $body)
            Write-Host "Папка '$folderName' создана в сейфе '$($this.getVault($vaultId).name)'"
        } catch {
            Write-Host "Ошибка создания папки: $($_.Exception.Message)"
        }
    }

    [void]addPassword([hashtable]$params) {
        try {
            # Проверяем, что переданные параметры не пустые
            if (-not $params) {
                Write-Host "Ошибка: параметры не указаны."
                return
            }

            # Проходим по всем элементам в массиве custom и применение ConvertToBase64 ко всем значениям
            foreach ($item in $params.custom) {
                if ($item -is [hashtable]) {
                    $keys = @($item.Keys)  # Сохраняем ключи в новый массив
                    foreach ($key in $keys) {
                        $item[$key] = $this.ConvertToBase64($item[$key])
                    }
                }
            }

            # Создаем хэш-таблицу для тела запроса
            $body = @{
                name            = $params['name']
                login           = $params['login']
                cryptedPassword = $this.ConvertToBase64($params['cryptedPassword'])
                url             = $params['url']
                description     = $params['description']
                custom          = $params['custom']
                color           = $params['color']
                attachments     = $params['attachments']
                tags            = $params['tags']
                masterHash      = $params['masterHash']
                vaultId         = $params['vaultId']
                folderId        = $params['folderId']
                shortcutId      = $params['shortcutId']
            }

            # Удаляем параметры, которые не были переданы
            $filteredBody = @{}
            foreach ($key in $body.Keys) {
                if ($body[$key] -ne $null -and $body[$key] -ne @()) {
                    $filteredBody[$key] = $body[$key]
                }
            }

            # Преобразуем в JSON
            $body = $filteredBody | ConvertTo-Json -Compress -Depth 10

            # Отправка запроса
            $response = $this.SendRequest("/passwords", 'POST', $this.ConvertToUnicodeEscape($body))
            if ($response.count -eq 0) {
                Write-Host "Пользователь не найдена."
                exit
            }

            Write-Host "Пользователь создан"
        } catch {
            Write-Host "Ошибка создания пароля: $($_.Exception.Message)"
        }
    }

    [object]getPassword([string]$stringId) {
       
        try {
            # Отправка запроса
            $response = $this.SendRequest("/passwords/$stringId", 'GET', $null)
            
            if ($response -eq $null) {
                Write-Host "Учетка не найдена"
                return $null
            }
                return $response.data
        } catch {
            Write-Host "Ошибка запроса: $($_.Exception.Message)"
            return $null
        }
    }

    [void]editPassword([string]$passwordId, [hashtable]$params) {
        try {
            # Проверяем, что переданы необходимые параметры
            if (-not $passwordId) {
                Write-Host "Ошибка: идентификатор учетки не указан"
                return
            }

            if (-not $params) {
                Write-Host "Ошибка: параметры не указаны"
                return
            }

            # Проходим по всем элементам в массиве custom и применяем ConvertToBase64 ко всем значениям
            foreach ($item in $params.custom) {
                if ($item -is [hashtable]) {
                    $keys = @($item.Keys)  # Сохраняем ключи в новый массив
                    foreach ($key in $keys) {
                        $item[$key] = $this.ConvertToBase64($item[$key])
                    }
                }
            }

            # Создаем хэш-таблицу для тела запроса
            $body = @{
                name            = $params['name']
                login           = $params['login']
                cryptedPassword = $this.ConvertToBase64($params['cryptedPassword'])
                url             = $params['url']
                description     = $params['description']
                custom          = $params['custom']
                color           = $params['color']
                attachments     = $params['attachments']
                tags            = $params['tags']
                masterHash      = $params['masterHash']
                vaultId         = $params['vaultId']
                folderId        = $params['folderId']
                shortcutId      = $params['shortcutId']
            }

            # Удаляем параметры, которые не были переданы
            $filteredBody = @{}
            foreach ($key in $body.Keys) {
                if ($body[$key] -ne $null -and $body[$key] -ne @()) {
                    $filteredBody[$key] = $body[$key]
                }
            }

            # Преобразуем в JSON
            $body = $filteredBody | ConvertTo-Json -Compress -Depth 10

            # Отправка запроса на обновление пароля
            $response = $this.SendRequest("/passwords/$passwordId", 'PUT', $this.ConvertToUnicodeEscape($body))

            if ($response.count -eq 0) {
                Write-Host "Ошибка: Учетка не найден или не обновлен"
                exit
            }

            Write-Host "Учетка обновлен"
        } catch {
            Write-Host "Ошибка обновления учетки: $($_.Exception.Message)"
        }
    }

    [void]movePassword([string]$passwordId, [hashtable]$params) {
        try {
            # Проверяем, что переданы необходимые параметры
            if (-not $passwordId) {
                Write-Host "Ошибка: идентификатор учетки не указан"
                return
            }

            if (-not $params) {
                Write-Host "Ошибка: параметры не указаны"
                return
            }

            # Создаем хэш-таблицу для тела запроса
            $body = @{
                folderTo        = $params['folderTo']
                vaultTo         = $params['vaultTo']
                cryptedPassword = $params['cryptedPassword']
                custom          = $params['custom']
                attachments     = $params['attachments']
            }

            # Удаляем параметры, которые не были переданы
            $filteredBody = @{}
            foreach ($key in $body.Keys) {
                if ($body[$key] -ne $null -and $body[$key] -ne @()) {
                    $filteredBody[$key] = $body[$key]
                }
            }

            # Преобразуем в JSON
            $body = $filteredBody | ConvertTo-Json -Compress -Depth 10

            # Отправка запроса на перемещение пароля
            $response = $this.SendRequest("/passwords/$passwordId/move", 'POST', $this.ConvertToUnicodeEscape($body))

            if ($response.count -eq 0) {
                Write-Host "Ошибка: учетка не перемещена"
                exit
            }

            Write-Host "Учетка успешно перемещен"
        } catch {
            Write-Host "Ошибка перемещения учетки: $($_.Exception.Message)"
        }
    }


    [object]searchPassword([hashtable]$params) {
        try {
            # Проверяем, что обязательные параметры переданы
            if (-not $params.ContainsKey('query')) {
                Write-Host "Ошибка: обязательные параметры 'query' не указаны."
                return $null
            }

            # Создаем хэш-таблицу для тела запроса
            $body = @{
                query = $params['query']
                vaultId = $params['vaultId']
                colors = $params['colors']  # Может быть $null
                tags = $params['tags']      # Может быть $null
                includeShared = $params['includeShared']  # По умолчанию $null
            }

            # Удаляем параметры, которые не были переданы
            $filteredBody = @{}
            foreach ($key in $body.Keys) {
                if ($body[$key] -ne $null -and $body[$key] -ne @()) {
                    $filteredBody[$key] = $body[$key]
                }
            }

            # Преобразуем в JSON
            $body = $filteredBody | ConvertTo-Json -Compress -Depth 10

            $response  =  $this.SendRequest("/passwords/search", 'POST', $this.ConvertToUnicodeEscape($body)).data

            if ($response.count -eq 0) {
                Write-Host "Учетка не найдена."
                return $null
            }
            Write-Host "Учетка найдена"
            return $response
        } catch {
            Write-Host "Ошибка создания пароля: $($_.Exception.Message)"
            return $null
        }
    }

    [object]searchFolder([hashtable]$params) {
        try {
            # Проверяем, что переданы необходимые параметры
            if (-not $params['query']) {
                Write-Host "Ошибка: строка запроса не указана."
                return $null
            }

            # Создаем хэш-таблицу для тела запроса
            $body = @{
                query   = $params['query']
                vaultId = $params['vaultId']
            }

            # Удаляем параметры, которые не были переданы
            $filteredBody = @{}
            foreach ($key in $body.Keys) {
                if ($body[$key] -ne $null -and $body[$key] -ne @()) {
                    $filteredBody[$key] = $body[$key]
                }
            }

            # Преобразуем в JSON
            $body = $filteredBody | ConvertTo-Json -Compress -Depth 10

            # Отправка запроса на поиск папки
            $response = $this.SendRequest("/folders/search", 'POST', $this.ConvertToUnicodeEscape($body))

            if ($response.count -eq 0) {
                Write-Host "Ошибка: папка не найдена."
                return $null
            }

            Write-Host "Папка найдена"
            return $response.data
        } catch {
            Write-Host "Ошибка поиска папки: $($_.Exception.Message)"
            return $null
        }
    }


}
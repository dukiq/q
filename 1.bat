@echo off
:: Перемещаем 1.py в TEMP
move "%~dp01.py" "%TEMP%\1.py" >nul 2>&1
:: Запускаем Python в новом окне
start "" python "%TEMP%\1.py"
:: Удаляем сам батник
(goto) 2>nul & del "%~f0"

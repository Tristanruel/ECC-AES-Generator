@echo off

if not exist "AES Keys" mkdir "AES Keys"
if not exist "Decrypted" mkdir "Decrypted"
if not exist "ECC Keys" mkdir "ECC Keys"
if not exist "Export" mkdir "Export"
if not exist "Import" mkdir "Import"
if not exist "Radiation Data" mkdir "Radiation Data"
if not exist "Randomness" mkdir "Randomness"
if not exist "Settings" mkdir "Settings"
if not exist "Settings\settings.txt" type nul > "Settings\settings.txt"

where python >nul 2>&1
if errorlevel 1 (
    echo Python not found. Installing Python...
    
    if not exist "python-3.11.5-amd64.exe" (
        echo Downloading Python installer...
        powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe' -OutFile 'python-3.11.5-amd64.exe'"
    )
    
    echo Running Python installer...
    python-3.11.5-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    
    echo Python installation complete.
) else (
    echo Python is already installed.
)

if not exist "vcpkg.exe" (
    echo vcpkg not found. Cloning vcpkg...
    git clone https://github.com/microsoft/vcpkg.git
    cd vcpkg
    bootstrap-vcpkg.bat
    cd ..
)

echo Installing C++ libraries via vcpkg...
vcpkg install openssl:x64-windows libzip:x64-windows gmp:x64-windows


echo Installing Python packages...
pip install pandas sympy tkinterdnd2

echo Installation complete.
pause

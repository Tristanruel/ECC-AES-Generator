@echo off

echo Starting data preprocessing...
python Data-preprocessing.py
if errorlevel 1 goto error

echo Starting von Neumann extractor...
von-neumann-extractor.exe
if errorlevel 1 goto error

echo Starting ECC generator...
ECC-generator.exe
if errorlevel 1 goto error

echo Starting AES generator...
AES-generator.exe
if errorlevel 1 goto error

echo All processes completed successfully.
goto end

:error
echo An error occurred. Exiting.
goto end

:end
pause

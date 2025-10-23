@echo off
echo ========================================
echo SSLSessionKeyExtractor - Compilation
echo ========================================

set SRC=SSLSessionKeyExtractor.cpp
set OUT=SSLSessionKeyExtractor.exe
set LIBS=comctl32.lib tdh.lib advapi32.lib user32.lib gdi32.lib

echo Compilation avec cl.exe (MSVC)...
cl.exe /nologo /EHsc /W4 /O2 /DUNICODE /D_UNICODE %SRC% /Fe:%OUT% /link %LIBS%

if %errorlevel% neq 0 (
    echo.
    echo Erreur de compilation!
    pause
    exit /b 1
)

echo.
echo Compilation reussie: %OUT%
echo.
echo ========================================
echo AVERTISSEMENT LEGAL
echo ========================================
echo Cet outil permet l'interception de cles TLS/SSL.
echo.
echo Usage AUTORISE uniquement pour:
echo   - Forensics legal (enquetes autorisees)
echo   - Tests en environnement controle
echo   - Analyse malware en laboratoire
echo.
echo Usage INTERDIT:
echo   - Interception non autorisee
echo   - Violation de confidentialite
echo.
echo LIMITATION TECHNIQUE:
echo   La methode ETW ne capture PAS les master secrets reels.
echo   Voir README.md pour alternatives (hooking, kernel debug).
echo.
echo IMPORTANT: Necessite droits administrateur
echo.
pause

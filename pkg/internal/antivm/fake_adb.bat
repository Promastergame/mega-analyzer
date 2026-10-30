@echo off
if "%~1"=="-s" shift & shift
if "%~1"=="shell" (
    if "%~2"=="getprop" (
        if "%~3"=="sys.boot_completed" (
            echo 1
            exit /b 0
        )
        echo [ro.product.model]: [Dummy]
        exit /b 0
    )
    echo Success
    exit /b 0
)
if "%~1"=="wait-for-device" (
    exit /b 0
)
echo Unknown command: %*
exit /b 1

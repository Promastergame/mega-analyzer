# APK без Android SDK

В `project/` находится небольшой проект на Smali: Activity, текстовый манифест
и строковый ресурс. Код напрямую обращается к классам Android через ссылки DEX;
`android.jar` для этого не нужен. При запуске эти классы предоставляет Android.

Из корня распакованного core-архива (Windows PowerShell):

```powershell
./analyzer.exe build ./examples/native-apk/project -o ./native-demo.apk
```

В Linux/macOS используйте `./analyzer` вместо `./analyzer.exe`.
Из исходников: `go run ./pkg/cmd/analyzer build ./examples/native-apk/project -o ./native-demo.apk`.

Сборка по умолчанию использует только встроенные реализации Smali→DEX,
AXML/ARSC, выравнивания ZIP и подписи APK. Java, aapt2, d8, zipalign и apksigner
не запускаются. APK подписывается отладочным ключом, не ключом издателя.

Для браузера упакуйте содержимое `project/` в ZIP, откройте «Собрать APK» и
загрузите архив. Разрешён и архив с одной внешней папкой проекта.
Скачайте `app.apk` из результатов завершённой сборки.

Это пример исходного Smali-проекта. Произвольные проекты Java/Kotlin/Gradle
требуют соответствующих компиляторов, которых во встроенном сборщике нет.
Успешная проверка структуры и подписи не заменяет запуск на Android.

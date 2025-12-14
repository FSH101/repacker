# DecryptCFG (Windows .exe via GitHub Actions)

Этот репозиторий собирает Windows `.exe` из Python-скрипта с GUI (Tkinter).

## Как получить .exe

1) Залей эти файлы в новый репозиторий GitHub (ветка `main`).
2) Открой вкладку **Actions** → **Build Windows EXE** → **Run workflow**.
3) Дождись завершения job `build`.
4) Скачай артефакт **DecryptCFG-windows** — внутри будет `DecryptCFG.exe`.

## Локальная сборка (если надо)

```bash
python -m pip install -r requirements.txt
pyinstaller --onefile --windowed decrypt_gui.py --name DecryptCFG
```
Готовый файл будет в `dist/DecryptCFG.exe`.

## Запуск

- Просто запускаешь `DecryptCFG.exe`, выбираешь входной `.cfg` и папку, жмёшь "Декодировать".
- Результат сохраняется как `<имя>_decrypted.cfg` в выбранной папке.

# VGBD Unpacker (decrypt + unpack)

This repo builds Windows `.exe` using GitHub Actions (PyInstaller).

## Local run
```bash
pip install -r requirements.txt
python vgbd_cli.py some.img -o out_dir --keep-paths
python vgbd_gui.py
```

## Download the EXE
- Go to **Actions** → open the latest run → **Artifacts** → download the `vgbd-unpacker-windows` artifact.
- Or push a tag like `v1.0.0` to get a GitHub Release with attached `.exe`.

# Ethereum Wallet Creator

A simple Python-based Ethereum wallet creator with a basic GUI built using Tkinter.

## Features

- Generate a new Ethereum wallet
- Import an existing wallet from a validated private key field
- Keep private keys hidden by default and reveal them only briefly when requested
- Export local, encrypted JSON keystore files without overwriting existing backups
- Sign arbitrary messages
- Copy the public wallet address without exposing the private key

## Getting Started

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the app:

```bash
python wallet_app.py
```

## Testing

Run the regression tests with:

```bash
python -m unittest discover -s tests -v
```

## Notes

- Keep your private key secure. Do not share it.
- The app uses a local GUI and stores keystore files only when you explicitly export them.
- The app does not send private keys or addresses over the network.

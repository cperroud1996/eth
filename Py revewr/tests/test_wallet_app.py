import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

import wallet_app


class FakeWidget:
    def __init__(self, value=""):
        self.value = value
        self.text = ""
        self.options = {}

    def get(self):
        return self.value

    def set(self, value):
        self.value = value

    def delete(self, *_args):
        self.value = ""
        self.text = ""

    def insert(self, _index, value):
        self.value += value
        self.text += value

    def config(self, **kwargs):
        self.options.update(kwargs)


class FakeRoot:
    def __init__(self):
        self.cancelled = []
        self.timer_count = 0

    def after(self, _delay, _callback):
        self.timer_count += 1
        return f"timer-{self.timer_count}"

    def after_cancel(self, timer_id):
        self.cancelled.append(timer_id)


class WalletAppTests(unittest.TestCase):
    def setUp(self):
        self.original_account = wallet_app.active_account
        self.original_root = wallet_app.root
        wallet_app.address_var = FakeWidget()
        wallet_app.private_key_entry = FakeWidget()
        wallet_app.private_key_display = FakeWidget()
        wallet_app.output_text = FakeWidget()
        wallet_app.status_label = FakeWidget()
        wallet_app.root = FakeRoot()
        wallet_app.reveal_timer_id = None

    def tearDown(self):
        wallet_app.active_account = self.original_account
        wallet_app.root = self.original_root
        wallet_app.reveal_timer_id = None

    def test_create_new_wallet_populates_address_without_logging_key(self):
        wallet_app.create_new_wallet()

        self.assertTrue(wallet_app.address_var.value.startswith("0x"))
        self.assertNotIn(wallet_app.active_account.key.hex(), wallet_app.output_text.text)
        self.assertEqual(wallet_app.status_label.options["text"], "Wallet ready. The private key remains hidden.")

    def test_import_wallet_accepts_prefixed_private_key_and_clears_input(self):
        account = Account.from_key(bytes.fromhex("01" * 32))
        wallet_app.private_key_entry.value = f"0x{account.key.hex()}"

        wallet_app.import_wallet()

        self.assertEqual(wallet_app.active_account.address, account.address)
        self.assertEqual(wallet_app.address_var.value, account.address)
        self.assertEqual(wallet_app.private_key_entry.value, "")
        self.assertIn("supplied private key was cleared", wallet_app.output_text.text)

    def test_private_key_validation_rejects_non_hex_and_oversized_input(self):
        self.assertTrue(wallet_app.validate_private_key_input("0x"))
        self.assertTrue(wallet_app.validate_private_key_input("ab" * 32))
        self.assertFalse(wallet_app.validate_private_key_input("DROP TABLE"))
        self.assertFalse(wallet_app.validate_private_key_input("a" * 67))

    def test_normalize_private_key_requires_exactly_32_bytes(self):
        self.assertEqual(wallet_app.normalize_private_key("0x" + "02" * 32), bytes.fromhex("02" * 32))
        with self.assertRaises(ValueError):
            wallet_app.normalize_private_key("02" * 31)

    @patch("wallet_app.messagebox.askyesno", return_value=True)
    def test_revealing_again_resets_the_previous_hide_timer(self, _askyesno):
        wallet_app.active_account = Account.from_key(bytes.fromhex("06" * 32))

        wallet_app.reveal_private_key()
        wallet_app.reveal_private_key()

        self.assertEqual(wallet_app.root.cancelled, ["timer-1"])
        self.assertEqual(wallet_app.reveal_timer_id, "timer-2")
        self.assertEqual(wallet_app.private_key_display.value, wallet_app.active_account.key.hex())

    @patch("wallet_app.simpledialog.askstring", return_value="hello")
    def test_sign_message_uses_current_message_hash_api(self, _askstring):
        account = Account.from_key(bytes.fromhex("03" * 32))
        wallet_app.active_account = account

        wallet_app.sign_message()

        output_lines = wallet_app.output_text.text.splitlines()
        signature = output_lines[1].split(": ", 1)[1]
        recovered = Account.recover_message(
            encode_defunct(text="hello"),
            signature=signature,
        )
        self.assertEqual(recovered, account.address)
        self.assertTrue(output_lines[2].startswith("Message hash: "))
        self.assertNotIn("Message: hello", wallet_app.output_text.text)
        self.assertEqual(wallet_app.status_label.options["text"], "Message signed locally.")

    @patch("wallet_app.simpledialog.askstring", side_effect=["test-password", "test-password"])
    def test_exported_keystore_decrypts_to_active_key(self, _askstring):
        account = Account.from_key(bytes.fromhex("04" * 32))
        wallet_app.active_account = account

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "wallet.json"
            with patch("wallet_app.filedialog.asksaveasfilename", return_value=str(path)):
                wallet_app.export_keystore()

            keystore = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(Account.decrypt(keystore, "test-password"), account.key)
        self.assertEqual(wallet_app.status_label.options["text"], "Encrypted keystore exported locally.")

    @patch("wallet_app.messagebox.showerror")
    @patch("wallet_app.filedialog.asksaveasfilename", return_value="blocked/wallet.json")
    @patch("wallet_app.simpledialog.askstring", side_effect=["test-password", "test-password"])
    @patch("wallet_app.os.open", side_effect=PermissionError("access denied"))
    def test_export_keystore_reports_write_errors(
        self,
        _open,
        _askstring,
        _save_dialog,
        showerror,
    ):
        wallet_app.active_account = Account.from_key(bytes.fromhex("05" * 32))

        wallet_app.export_keystore()

        showerror.assert_called_once()
        self.assertIn("Failed to save keystore", showerror.call_args.args[1])


if __name__ == "__main__":
    unittest.main()

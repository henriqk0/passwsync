"""check_bindings.py: negative tests per binding rule B1-B6 over the generated-binding sample
of the good fixture (with its own inventory), plus the positive case."""

import unittest

from support import PolicyCase, mutate, run_checker

F = "bindings/io/github/henriqk0/passwsync/core/passwsync_ffi.kt"
BA = "kotlin.ByteArray"


def repl(find, replace):
    return (find, replace)


def secret(signature_find, param):
    """Changes `param`'s type in the line containing `signature_find` to String."""
    return ("param", signature_find, param)


CASES = {
    "B1_package": ("B1", repl("package io.github.henriqk0.passwsync.core", "package uniffi.passwsync_ffi")),
    "B1_coroutines_import": ("B1", repl("import com.sun.jna.Library", "import com.sun.jna.Library\nimport kotlinx.coroutines.CoroutineScope")),
    "B1_android_import": ("B1", repl("import com.sun.jna.Library", "import com.sun.jna.Library\nimport android.util.Log")),
    "B1_library_name": ("B1", repl('    return "passwsync_ffi"', '    return "other_ffi"')),
    "B2_create_password": ("B2", secret("`createWallet`", "password")),
    "B2_create_confirm": ("B2", secret("`createWallet`", "confirm")),
    "B2_unlock_password": ("B2", secret("`unlockWallet`", "password")),
    "B2_change_current": ("B2", secret("`changePassword`", "current")),
    "B2_change_new": ("B2", secret("`changePassword`", "new")),
    "B2_change_confirm": ("B2", secret("`changePassword`", "confirm")),
    "B2_join_code": ("B2", secret("`joinPairing`", "code")),
    "B2_redeem_code": ("B2", secret("`redeemInvitation`", "code")),
    "B2_open_received_password": ("B2", secret("`openReceived`", "password")),
    "B2_open_pending_password": ("B2", secret("`openPendingWithPassword`", "password")),
    "B2_seal_plaintext": ("B2", secret("`seal`", "plaintext")),
    "B2_open_sealed": ("B2", secret("`open`", "sealed")),
    "B2_clipboard_value": ("B2", secret("`setSensitive`", "value")),
    "B2_credential_input_password": ("B2", repl("var `password`: kotlin.ByteArray?", "var `password`: kotlin.String?")),
    "B2_secret_key_field": ("B2", repl("var `dataDir`: kotlin.String", "var `dataDir`: kotlin.String\n    , \n    var `secretKey`: kotlin.String")),
    "B2_seal_returns_text": ("B2", repl("`plaintext`: kotlin.ByteArray): kotlin.ByteArray", "`plaintext`: kotlin.ByteArray): kotlin.String")),
    "B3_summary_password": ("B3", repl("    var `conflicted`: kotlin.Boolean", "    var `conflicted`: kotlin.Boolean\n    , \n    var `password`: kotlin.ByteArray")),
    "B3_summary_notes": ("B3", repl("    var `conflicted`: kotlin.Boolean", "    var `conflicted`: kotlin.Boolean\n    , \n    var `notes`: kotlin.String")),
    "B3_details_password": ("B3", repl("    var `modifiedAt`: kotlin.Long", "    var `modifiedAt`: kotlin.Long\n    , \n    var `password`: kotlin.ByteArray")),
    "B3_other_record_password": ("B3", repl("    var `eligibleInterfaces`: List<kotlin.String>", "    var `eligibleInterfaces`: List<kotlin.String>\n    , \n    var `password`: kotlin.ByteArray")),
    "B4_method_added": ("B4", repl("    fun `multicastWanted`(): kotlin.Boolean\n", "    fun `multicastWanted`(): kotlin.Boolean\n    \n    fun `exportAll`(): kotlin.String\n")),
    "B4_method_removed": ("B4", repl("    fun `multicastWanted`(): kotlin.Boolean\n", "")),
    "B4_port_method_removed": ("B4", repl("    fun `reset`()\n", "")),
    "B4_top_level_function": ("B4", repl("public interface Clipboard {", "fun `debugDump`(): kotlin.String = \"\"\n\npublic interface Clipboard {")),
    "B4_constructor_removed": ("B4", repl("        fun `start`(", "        fun `begin`(")),
    "B5_variant_added": ("B5", repl("        class Platform(message: String) : CoreException(message)", "        class Platform(message: String) : CoreException(message)\n        class Extra(message: String) : CoreException(message)")),
    "B5_variant_removed": ("B5", repl("        class Platform(message: String) : CoreException(message)\n", "")),
    "B6_suspend": ("B6", repl("    fun `pairing`(): PairingView", "    suspend fun `pairing`(): PairingView")),
    "B6_flow": ("B6", repl("    fun `invitation`(): InvitationView?", "    fun `invitation`(): Flow<InvitationView>")),
}


def apply(root, change):
    path = root / F
    if change[0] == "param":
        _, where, param = change
        text = path.read_text(encoding="utf-8")
        start = text.index(f"fun {where}(")
        end = text.index("\n", start)
        line = text[start:end]
        new = line.replace(f"`{param}`: {BA}", f"`{param}`: kotlin.String", 1)
        assert new != line, (where, param)
        path.write_text(text[:start] + new + text[end:], encoding="utf-8")
    else:
        mutate(path, change[0], change[1])


class CheckBindings(PolicyCase):
    checker = "check_bindings"

    def run_on(self, root):
        return run_checker(self.checker, root / "bindings", "--inventory", str(root / "bindings-inventory.txt"))

    def test_good_fixture_passes(self):
        self.assertPasses(self.tree())

    def test_the_contract_lists_37_errors(self):
        import check_bindings
        names = check_bindings.contract_errors(check_bindings.DEFAULT_CONTRACT)
        self.assertEqual(len(names), 37)
        self.assertIn("KdfParamsOutOfRange", names)
        self.assertIn("ProtectionMissing", names)

    def test_usage_error(self):
        self.assertEqual(run_checker(self.checker, "--bogus")[0], 64)
        self.assertEqual(run_checker(self.checker, "/nonexistent")[0], 64)

    def test_no_kotlin_file_fails(self):
        root = self.tree()
        (root / F).unlink()
        self.assertFails(root, "B1")


def make(rule, change):
    def test(self):
        root = self.tree()
        apply(root, change)
        self.assertFails(root, rule)
    return test


for case, (rule, change) in CASES.items():
    setattr(CheckBindings, f"test_{case}", make(rule, change))


if __name__ == "__main__":
    unittest.main()

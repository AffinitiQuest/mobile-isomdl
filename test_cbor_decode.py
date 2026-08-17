#!/usr/bin/env python3
"""
Diagnose "got tstr, expected bstr" in a DeviceResponse CBOR blob.

Usage:
    python3 test_cbor_decode.py <hex_file>
    echo "<hex>" | python3 test_cbor_decode.py

The script decodes the CBOR and reports the type of every field that the
isomdl Rust library expects to be a byte string (bstr):
  - issuerSigned.issuerAuth  (COSE_Sign1 array: protected, payload, signature)
  - deviceSigned.nameSpaces  (Tag24 wrapper: must be Tag(24, bstr))
  - deviceSigned.deviceAuth  (COSE_Sign1/COSE_Mac0 array elements)
  - Each IssuerSignedItem.random inside Tag24-wrapped items
"""

import sys
import cbor2
import binascii


def cbor_type(v) -> str:
    if isinstance(v, bytes):
        return f"bstr ({len(v)} bytes)"
    if isinstance(v, str):
        return f"tstr ({len(v)} chars) *** WRONG ***"
    if isinstance(v, list):
        return f"array ({len(v)} items)"
    if isinstance(v, dict):
        return f"map ({len(v)} entries)"
    if isinstance(v, cbor2.CBORTag):
        return f"tag({v.tag}, {cbor_type(v.value)})"
    return type(v).__name__


def check_cose(label: str, cose_value):
    """Check a COSE_Sign1 or COSE_Mac0 array for bstr fields."""
    if isinstance(cose_value, cbor2.CBORTag):
        print(f"  {label}: wrapped in tag({cose_value.tag})")
        cose_value = cose_value.value
    if not isinstance(cose_value, list):
        print(f"  {label}: NOT an array — {cbor_type(cose_value)}")
        return
    print(f"  {label}: array of {len(cose_value)} elements")
    labels = ["protected", "unprotected", "payload", "signature"]
    for i, elem in enumerate(cose_value):
        lbl = labels[i] if i < len(labels) else str(i)
        t = cbor_type(elem)
        marker = " *** WRONG (should be bstr) ***" if isinstance(elem, str) and lbl in ("protected", "payload", "signature") else ""
        print(f"    [{i}] {lbl}: {t}{marker}")
        # If protected header is bytes, try to decode it
        if lbl == "protected" and isinstance(elem, bytes) and elem:
            try:
                hdr = cbor2.loads(elem)
                print(f"         decoded protected header: {hdr}")
            except Exception:
                pass


def check_tag24(label: str, value):
    """Check a Tag24-wrapped value: should be Tag(24, bstr)."""
    if isinstance(value, cbor2.CBORTag):
        print(f"  {label}: Tag({value.tag}, {cbor_type(value.value)})", end="")
        if value.tag != 24:
            print(f"  *** WRONG tag (expected 24)")
        elif not isinstance(value.value, bytes):
            print(f"  *** WRONG inner type (expected bstr)")
        else:
            print()  # OK
            # Decode the inner bytes
            try:
                inner = cbor2.loads(value.value)
                print(f"    inner decoded type: {type(inner).__name__}")
            except Exception as e:
                print(f"    *** inner bytes failed to decode: {e}")
    else:
        print(f"  {label}: {cbor_type(value)}  *** WRONG (expected Tag(24, bstr)) ***")


def inspect_issuer_signed_items(ns_name: str, items):
    """Check IssuerSignedItemBytes = Tag24<IssuerSignedItem> array."""
    if not isinstance(items, list):
        print(f"    namespace items: NOT an array — {cbor_type(items)}")
        return
    for idx, item_tag in enumerate(items):
        prefix = f"    item[{idx}]"
        if not isinstance(item_tag, cbor2.CBORTag) or item_tag.tag != 24:
            print(f"{prefix}: {cbor_type(item_tag)} *** expected Tag(24, bstr) ***")
            continue
        inner = item_tag.value
        if not isinstance(inner, bytes):
            print(f"{prefix}: Tag(24, {cbor_type(inner)}) *** inner must be bstr ***")
            continue
        try:
            signed_item = cbor2.loads(inner)
        except Exception as e:
            print(f"{prefix}: Tag(24, bstr) but inner decode failed: {e}")
            continue
        if not isinstance(signed_item, dict):
            print(f"{prefix}: Tag(24, bstr→{type(signed_item).__name__}) *** expected map ***")
            continue
        random_val = signed_item.get("random")
        elem_id = signed_item.get("elementIdentifier", "?")
        random_type = cbor_type(random_val) if random_val is not None else "MISSING"
        bad = " *** WRONG ***" if not isinstance(random_val, bytes) else ""
        print(f"{prefix} '{elem_id}': random={random_type}{bad}")


def inspect_device_response(data):
    print("=== DeviceResponse top-level keys ===")
    print(f"  version: {data.get('version')}")
    docs = data.get("documents", [])
    print(f"  documents: {len(docs)} document(s)")
    status = data.get("status")
    print(f"  status: {status}")

    for doc_idx, doc in enumerate(docs):
        if not isinstance(doc, dict):
            print(f"\n[doc {doc_idx}] not a map: {cbor_type(doc)}")
            continue
        doc_type = doc.get("docType", "?")
        print(f"\n=== Document [{doc_idx}]: {doc_type} ===")
        print(f"  keys: {list(doc.keys())}")

        # ---- issuerSigned ----
        issuer_signed = doc.get("issuerSigned")
        if issuer_signed is None:
            print("  issuerSigned: MISSING")
        else:
            print(f"\n  --- issuerSigned ---")
            print(f"  issuerSigned keys: {list(issuer_signed.keys()) if isinstance(issuer_signed, dict) else cbor_type(issuer_signed)}")
            if isinstance(issuer_signed, dict):
                # nameSpaces
                name_spaces = issuer_signed.get("nameSpaces")
                if name_spaces is not None:
                    if isinstance(name_spaces, dict):
                        print(f"  issuerSigned.nameSpaces: map with {len(name_spaces)} namespace(s)")
                        for ns, items in name_spaces.items():
                            print(f"    namespace '{ns}': {cbor_type(items)}")
                            if isinstance(items, list):
                                inspect_issuer_signed_items(ns, items)
                    else:
                        print(f"  issuerSigned.nameSpaces: {cbor_type(name_spaces)}")

                # issuerAuth (COSE_Sign1)
                issuer_auth = issuer_signed.get("issuerAuth")
                if issuer_auth is None:
                    print("  issuerSigned.issuerAuth: MISSING")
                else:
                    check_cose("issuerSigned.issuerAuth", issuer_auth)

        # ---- deviceSigned ----
        device_signed = doc.get("deviceSigned")
        if device_signed is None:
            print("\n  deviceSigned: MISSING *** (required for mDoc) ***")
        else:
            print(f"\n  --- deviceSigned ---")
            print(f"  deviceSigned keys: {list(device_signed.keys()) if isinstance(device_signed, dict) else cbor_type(device_signed)}")
            if isinstance(device_signed, dict):
                # nameSpaces (must be Tag24<DeviceNamespaces> = Tag(24, bstr))
                ns = device_signed.get("nameSpaces")
                if ns is None:
                    print("  deviceSigned.nameSpaces: MISSING")
                else:
                    check_tag24("deviceSigned.nameSpaces", ns)

                # deviceAuth
                device_auth = device_signed.get("deviceAuth")
                if device_auth is None:
                    print("  deviceSigned.deviceAuth: MISSING")
                elif isinstance(device_auth, dict):
                    for auth_key, auth_val in device_auth.items():
                        check_cose(f"deviceSigned.deviceAuth.{auth_key}", auth_val)
                else:
                    print(f"  deviceSigned.deviceAuth: {cbor_type(device_auth)}")


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            hex_str = f.read().strip()
    else:
        hex_str = sys.stdin.read().strip()

    # Strip any whitespace/newlines inside the hex string
    hex_str = "".join(hex_str.split())

    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as e:
        print(f"ERROR: invalid hex input: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Decoding {len(raw)} bytes of CBOR...")

    try:
        data = cbor2.loads(raw)
    except Exception as e:
        print(f"ERROR: top-level CBOR decode failed: {e}", file=sys.stderr)
        sys.exit(1)

    inspect_device_response(data)
    print("\nDone.")


if __name__ == "__main__":
    main()

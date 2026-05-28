#!/usr/bin/env python3
"""Simple NFC tag scanner using pyscard."""

from __future__ import annotations

from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from smartcard.util import toHexString


def transmit(card_connection, apdu: list[int], label: str) -> tuple[list[int], int, int]:
    """Send APDU command and print a compact trace line."""
    response, sw1, sw2 = card_connection.transmit(apdu)
    print(f"{label:<22} APDU={toHexString(apdu)}  SW={sw1:02X}{sw2:02X}")
    return response, sw1, sw2


def parse_ndef_text(raw: list[int]) -> str | None:
    """
    Parse a very common NDEF Text record payload.
    Returns None if format does not match a simple text record.
    """
    if len(raw) < 5:
        return None

    # Minimal check for short NDEF text record:
    # D1 01 <len> 54 <status+lang+text...>
    if raw[0] != 0xD1 or raw[1] != 0x01 or raw[3] != 0x54:
        return None

    payload_len = raw[2]
    payload = raw[4 : 4 + payload_len]
    if not payload:
        return None

    status = payload[0]
    lang_len = status & 0x3F
    if len(payload) < 1 + lang_len:
        return None

    text_bytes = bytes(payload[1 + lang_len :])
    try:
        return text_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return text_bytes.decode("latin-1", errors="replace")


def read_ndef(card_connection) -> None:
    """
    Try to read NDEF from NFC Forum Type 4 tag:
    1) Select NDEF Application
    2) Select Capability Container file
    3) Read CC + NDEF file id
    4) Select NDEF file and read NLEN + payload
    """
    # Select NDEF Tag Application (AID D2760000850101)
    _, sw1, sw2 = transmit(
        card_connection,
        [0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00],
        "Select NDEF app",
    )
    if (sw1, sw2) != (0x90, 0x00):
        print("NDEF app konnte nicht ausgewaehlt werden.")
        return

    # Select CC file E103
    _, sw1, sw2 = transmit(
        card_connection,
        [0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03],
        "Select CC file",
    )
    if (sw1, sw2) != (0x90, 0x00):
        print("CC file konnte nicht ausgewaehlt werden.")
        return

    cc_data, sw1, sw2 = transmit(
        card_connection,
        [0x00, 0xB0, 0x00, 0x00, 0x0F],
        "Read CC",
    )
    if (sw1, sw2) != (0x90, 0x00) or len(cc_data) < 15:
        print("CC konnte nicht gelesen werden.")
        return

    # In many tags, NDEF file id is at CC bytes 9 and 10
    ndef_file_id = cc_data[9:11]
    if len(ndef_file_id) != 2:
        print("Konnte NDEF File-ID nicht aus CC bestimmen.")
        return

    _, sw1, sw2 = transmit(
        card_connection,
        [0x00, 0xA4, 0x00, 0x0C, 0x02, ndef_file_id[0], ndef_file_id[1]],
        "Select NDEF file",
    )
    if (sw1, sw2) != (0x90, 0x00):
        print("NDEF file konnte nicht ausgewaehlt werden.")
        return

    nlen_raw, sw1, sw2 = transmit(
        card_connection,
        [0x00, 0xB0, 0x00, 0x00, 0x02],
        "Read NLEN",
    )
    if (sw1, sw2) != (0x90, 0x00) or len(nlen_raw) != 2:
        print("NLEN konnte nicht gelesen werden.")
        return

    nlen = (nlen_raw[0] << 8) | nlen_raw[1]
    if nlen == 0:
        print("Tag enthaelt keine NDEF-Nutzdaten.")
        return

    if nlen > 240:
        print(f"NDEF ist {nlen} Bytes lang, lese erste 240 Bytes.")
        read_len = 240
    else:
        read_len = nlen

    data, sw1, sw2 = transmit(
        card_connection,
        [0x00, 0xB0, 0x00, 0x02, read_len],
        "Read NDEF payload",
    )
    if (sw1, sw2) != (0x90, 0x00):
        print("NDEF-Payload konnte nicht gelesen werden.")
        return

    print(f"NDEF raw: {toHexString(data)}")
    text = parse_ndef_text(data)
    if text is not None:
        print(f"NDEF Text: {text}")


def main() -> None:
    available_readers = readers()
    if not available_readers:
        print("Kein Smartcard/NFC-Reader gefunden.")
        print("Installiere ggf. Treiber und pruefe den Reader.")
        return

    print("Verfuegbare Reader:")
    for idx, reader in enumerate(available_readers, start=1):
        print(f"  [{idx}] {reader}")

    reader = available_readers[0]
    print(f"\nNutze Reader: {reader}")
    print("Bitte NFC-Tag auflegen...")

    connection = reader.createConnection()
    try:
        connection.connect()
    except NoCardException:
        print("Kein Tag erkannt. Lege ein NFC-Tag auf und starte erneut.")
        return
    except Exception as exc:  # pragma: no cover - hardware specific
        print(f"Verbindung fehlgeschlagen: {exc}")
        return

    print("Tag verbunden.")

    uid, sw1, sw2 = transmit(connection, [0xFF, 0xCA, 0x00, 0x00, 0x00], "Get UID")
    if (sw1, sw2) == (0x90, 0x00):
        print(f"UID: {toHexString(uid)}")
    else:
        print("UID konnte nicht gelesen werden.")

    read_ndef(connection)


if __name__ == "__main__":
    main()

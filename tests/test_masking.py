from bharosa.masking import (aadhaar_valid, contains_unmasked_pii, luhn_valid, mask_text, verhoeff_check_digit,
                             verhoeff_valid)


def synthetic_aadhaar() -> str:
    base = "23456789012"  # synthetic, built only to satisfy the checksum
    return base + verhoeff_check_digit(base)


def test_verhoeff_and_luhn():
    a = synthetic_aadhaar()
    assert verhoeff_valid(a) and aadhaar_valid(a)
    assert not aadhaar_valid(a[:-1] + str((int(a[-1]) + 1) % 10))
    assert luhn_valid("4111111111111111")  # well-known test card number
    assert not luhn_valid("4111111111111112")


def test_masks_each_kind():
    a = synthetic_aadhaar()
    text = (f"Aadhaar {a[:4]} {a[4:8]} {a[8:]}, card 4111 1111 1111 1111, call +91 99999 00001, "
            "OTP is 482913, pay ramesh.k@oksbi, PAN ABCDE1234F, a/c no 123456789012, IFSC SBIN0001234")
    m = mask_text(text)
    assert "<AADHAAR>" in m.text
    assert "<CARD_LAST4:1111>" in m.text
    assert "<PHONE_1>" in m.text
    assert "<OTP>" in m.text and "482913" not in m.text
    assert "@oksbi" in m.text and "ramesh.k" not in m.text
    assert "<PAN>" in m.text
    assert "<ACCOUNT>" in m.text
    assert "SBIN0001234" in m.text  # IFSC is public and kept
    assert contains_unmasked_pii(m.text) == []
    assert m.counts["PHONE"] == 1


def test_invalid_checksum_numbers_are_not_masked_as_aadhaar():
    m = mask_text("Order number 1234 5678 9012")
    assert "<AADHAAR>" not in m.text


def test_same_value_gets_same_token_and_masking_is_idempotent():
    m = mask_text("Call 9999900001 or 9999900001 or 9999900002")
    assert m.text.count("<PHONE_1>") == 2 and "<PHONE_2>" in m.text
    assert mask_text(m.text).text == m.text


def test_token_map_only_in_memory():
    m = mask_text("Call 9999900001")
    assert m.token_map["<PHONE_1>"] == "9999900001"
    assert "token_map" not in repr(m)


def test_detects_leftover_pii():
    assert "PHONE" in contains_unmasked_pii("call 9999900001")
    assert "UPI_ID" in contains_unmasked_pii("pay ramesh.k@oksbi.")
    assert contains_unmasked_pii(mask_text("pay ramesh.k@oksbi.").text) == []
    assert contains_unmasked_pii("nothing here") == []

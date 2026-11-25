"""Regenerate the synthetic demo QR images in samples/qr/ from fixed payloads.

Run: python scripts/make_samples.py
"""

from pathlib import Path

import qrcode

ROOT = Path(__file__).resolve().parents[1]
QR = {
    "shop.png": "upi://pay?pa=sharmagrocery.demo@okaxis&pn=Sharma%20Grocery&am=240&cu=INR&tn=Order%2017",
    "milk.png": "upi://pay?pa=nandini.milk.demo@ybl&pn=Nandini%20Milk%20Booth&cu=INR",
    "cashback.png": "upi://pay?pa=rewards.desk.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&cu=INR"
                    "&tn=Scan%20to%20receive%20cashback%20Rs%204999",
    "refund.png": "upi://pay?pa=refund.helpdesk.demo@ybl&pn=Amazon%20Refund%20Dept&am=1&cu=INR"
                  "&tn=Refund%20of%20Rs%202500",
    "not_upi.png": "https://bit.ly/claim-upi-reward",
}


def main() -> None:
    out = ROOT / "samples" / "qr"
    out.mkdir(parents=True, exist_ok=True)
    for name, payload in QR.items():
        img = qrcode.make(payload, box_size=8, border=4)
        img.save(out / name)
        print("wrote", out / name)


if __name__ == "__main__":
    main()

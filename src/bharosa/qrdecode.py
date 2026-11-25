"""Decode QR codes from an image file or a webcam frame with OpenCV (no system libraries needed)."""

from __future__ import annotations

from pathlib import Path

MAX_IMAGE_BYTES = 5 * 1024 * 1024


class QRDecodeError(ValueError):
    pass


def _detector():
    import cv2

    return cv2, cv2.QRCodeDetector()


def decode_image(path: str | Path) -> str:
    path = Path(path)
    if not path.is_file():
        raise QRDecodeError(f"no such image: {path}")
    if path.stat().st_size > MAX_IMAGE_BYTES:
        raise QRDecodeError("image is larger than the 5 MB limit")
    cv2, det = _detector()
    import numpy as np

    data = np.frombuffer(path.read_bytes(), dtype=np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)  # imdecode handles non-ASCII Windows paths
    if img is None:
        raise QRDecodeError("the file is not an image OpenCV can read")
    return decode_array(img)


def decode_bytes(data: bytes) -> str:
    """Decode a QR from image bytes (a photo sent to the chat bot)."""
    if len(data) > MAX_IMAGE_BYTES:
        raise QRDecodeError("image is larger than the 5 MB limit")
    cv2, det = _detector()
    import numpy as np

    img = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise QRDecodeError("the file is not an image OpenCV can read")
    return decode_array(img)


def decode_array(img) -> str:
    cv2, det = _detector()
    attempts = [img]
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    attempts.append(gray)
    attempts.append(cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1])
    h, w = gray.shape[:2]
    if max(h, w) < 400:
        attempts.append(cv2.resize(gray, None, fx=3, fy=3, interpolation=cv2.INTER_NEAREST))
    # Add a quiet zone in case the QR touches the image border.
    attempts.append(cv2.copyMakeBorder(gray, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255))
    for a in attempts:
        text, points, _ = det.detectAndDecode(a)
        if text:
            return text
    raise QRDecodeError("no readable QR code found in the image (try --payload with the raw upi:// string)")


def decode_camera(index: int = 0, timeout_seconds: float = 20.0) -> str:
    import time

    cv2, det = _detector()
    cap = cv2.VideoCapture(index)
    if not cap.isOpened():
        raise QRDecodeError("could not open the webcam")
    try:
        end = time.time() + timeout_seconds
        while time.time() < end:
            ok, frame = cap.read()
            if not ok:
                continue
            text, _, _ = det.detectAndDecode(frame)
            if text:
                return text
    finally:
        cap.release()
    raise QRDecodeError("no QR code seen on the webcam")

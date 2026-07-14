"""
qr_reader.py
Decodes a QR code image and extracts the embedded URL/text.
"""

from PIL import Image
from pyzbar.pyzbar import decode


def read_qr_code(image_file) -> str | None:
    """
    image_file: a file-like object or path to an image containing a QR code.
    Returns the decoded string, or None if no QR code was found.
    """
    img = Image.open(image_file)
    results = decode(img)
    if not results:
        return None
    return results[0].data.decode("utf-8")

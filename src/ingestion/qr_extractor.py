def extract_qr_codes(image_bytes: bytes) -> List[str]:
    """Decode QR codes from image bytes.

    Uses OpenCV's QRCodeDetector as the primary decoder.
    Falls back to pyzbar if OpenCV cannot decode.
    Handles empty bytes and invalid/unsupported images gracefully.

    Args:
        image_bytes: Raw image file bytes (PNG, JPEG, BMP, etc.).

    Returns:
        List of decoded QR code text values. Empty list if no QR codes
        found or if the image cannot be decoded.

    Raises:
        Nothing. All errors are caught internally; an empty list is
        returned for any invalid input.
    """
    if not image_bytes:
        return []

    # Try OpenCV's QRCodeDetector first (no native ZBar dependency needed)
    import cv2
    from PIL import Image
    import numpy as np
    import io
    
    try:
        # Convert image bytes to OpenCV format
        pil_image = Image.open(io.BytesIO(image_bytes))
        
        # Convert to RGB if necessary
        if pil_image.mode != "RGB":
            pil_image = pil_image.convert("RGB")
        
        img_array = np.array(pil_image)
        img_bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        
        # Detect and decode
        detector = cv2.QRCodeDetector()
        decoded, points, straight_qrcode = detector.detectAndDecode(img_bgr)
        
        if decoded:
            return [decoded]
    except Exception:
        pass
    
    # Fall back to pyzbar
    try:
        from PIL import Image as PILImage
        img = PILImage.open(io.BytesIO(image_bytes))
    except Exception:
        return []
    
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
    except Exception:
        # pyzbar not available (e.g. missing native ZBar on Windows)
        return []
    
    try:
        decoded_objects = pyzbar_decode(img)
    except Exception:
        return []
    
    return [obj.data.decode("utf-8", errors="replace") for obj in decoded_objects]
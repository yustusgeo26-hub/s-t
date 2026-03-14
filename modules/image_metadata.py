from pathlib import Path
from typing import Dict

try:
    import exifread
except Exception:
    exifread = None

try:
    from PIL import Image
except Exception:
    Image = None


def _extract_gps(tags: Dict) -> Dict:
    gps = {}
    for key in [
        "GPS GPSLatitude",
        "GPS GPSLatitudeRef",
        "GPS GPSLongitude",
        "GPS GPSLongitudeRef",
    ]:
        if key in tags:
            gps[key] = str(tags[key])
    return gps


def analyze_image(path: str) -> Dict:
    file_path = Path(path)
    if not file_path.exists():
        return {"image": path, "error": "File does not exist."}

    result = {"image": str(file_path), "format": None, "size": None, "metadata": {}, "gps": {}}

    if Image is None:
        result["image_error"] = "Pillow dependency is not installed"
    else:
        try:
            with Image.open(file_path) as img:
                result["format"] = img.format
                result["size"] = img.size
        except Exception as e:
            result["image_error"] = str(e)

    if exifread is None:
        result["exif_error"] = "exifread dependency is not installed"
    else:
        try:
            with file_path.open("rb") as f:
                tags = exifread.process_file(f, details=False)
            keys = ["Image Model", "EXIF DateTimeOriginal", "Image Software"]
            result["metadata"] = {k: str(tags[k]) for k in keys if k in tags}
            result["gps"] = _extract_gps(tags)
        except Exception as e:
            result["exif_error"] = str(e)

    return result

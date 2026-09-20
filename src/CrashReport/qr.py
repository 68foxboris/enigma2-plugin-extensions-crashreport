"""Generate a QR locally: no external QR service receives the tracking number."""
from os import close, unlink
from tempfile import mkstemp


def create_qr(url):
	import qrcode
	from PIL import Image
	code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
	code.add_data(url)
	code.make(fit=True)
	code.box_size = max(1, min(8, 320 // (code.modules_count + 8)))
	qr = code.make_image(fill_color="black", back_color="white").get_image().convert("RGB")
	if qr.width > 320:
		raise ValueError("The report URL is too long for the QR display.")
	canvas = Image.new("RGB", (320, 320), "white")
	canvas.paste(qr, ((320 - qr.width) // 2, (320 - qr.height) // 2))
	fd, path = mkstemp(prefix="openatv-report-", suffix=".png")
	close(fd)
	try:
		canvas.save(path, "PNG")
	except Exception:
		unlink(path)
		raise
	return path

import ssl
import OpenSSL
import datetime

def check(hostname):
	port = 443
	cert = ssl.get_server_certificate((hostname, port))
	x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
	print("\n[i] Checking SSL Certificate for {}\n".format(hostname))
	expiry_date = x509.get_notAfter()
	ssl_date_fmt = r'%Y%m%d%H%M%SZ'
	expires = datetime.datetime.strptime(str(expiry_date)[2:-1], ssl_date_fmt)
	print("[i] Certificate Information:\n")
	for i in x509.get_issuer().get_components():
		print("[+]", i[0].decode(), "=", i[1].decode())
	print("[+] Serial Number:", x509.get_serial_number())
	print("[+] Certificate Signature Algorithm:", x509.get_signature_algorithm().decode())
	print()
	if x509.has_expired():
		print("[i] Expired Certificate")
		print("[i] Certificate expired on", expires)
	else:
		print("[i] Certificate is valid")
		print("[i] Certificate will expire on", expires)

while True:
	try:
		hostname = input("=> ")
		if hostname.startswith("https://"):
			hostname = hostname[8:]
		elif hostname.startswith("http://"):
			hostname = hostname[7:]
		else:
			pass

		if hostname[-1:]=='/':
			hostname = hostname[:-1]

		check(hostname)
		print()

	except KeyboardInterrupt:
		break

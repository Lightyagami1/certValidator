def valid_string(val: str) -> bool:
    """ just string length check """
    return True if len(val) > 0 else False

def get_cert_cn(cert) -> str:
    try:
        return cert.get_subject().CN
    except:
        return 123  # ERROR_INVALID_NAME

def valid_fqdnIp(cert, fqdn_ip: str) -> int:

    san_vals = parse_vals(cert)
    if any(san_vals == err for err in [87, 123]):
        return san_vals

    if is_ip_address(fqdn_ip):
        ip_addresses_from_san = san_vals[1]

        if all(fqdn_ip != x for x in ip_addresses_from_san):
            dns_from_san = san_vals[2]
            if all(fqdn_ip != x for x in dns_from_san):
                return 80004  # CERTIFICATE_ERROR_IP_IN_WRONG_KEY
            else:
                return 80002  # CERTIFICATE_ERROR_IP_NOT_IN_SAN
        else:
            return 0

    else:
        if len(san_vals[2]) == 0:
            if get_cert_cn(cert) != fqdn_ip:
                return 80007  # CERTIFICATE_ERROR_DNS_DOES_NOT_MATCH_CN
            else:
                return 80003  # CERTIFICATE_ERROR_DNS_NOT_IN_SAN
        else:
            return 0

def validate_x509(cert, fqdn_ip: str) -> int:
    """ fqdn and certificate expiry checks """

    # not_before check
    now = datetime.datetime.now()
    current_time = now.strftime("%Y%m%d%H%M%S")
    not_before = cert.get_notBefore()
    not_before = str(not_before)[2:-2]
    if not_before > current_time:
        return 8005  # CERTIFICATE_ERROR_DATE_NOT_YET_VALID

    # not_after check below
    if cert.has_expired():
        return 8006  # CERTIFICATE_ERROR_DATE_EXPIRED

    return valid_fqdnIp(cert, fqdn_ip)

def validate_cert_file(file_name: str, fqdn_ip: str) -> int:
    """ Based on date, time and fqdn """
    cert = get_x509_from_file(file_name)
    if any(cert == x for x in [1006, 2]):
        return cert

    return validate_x509(cert, fqdn_ip)

def get_fqdn(certificate) -> str:
    fqdn_ip = certificate.get_subject().O
    return fqdn_ip

def is_ip_address(addr: str) -> bool:
    """ Return bool for both ipv4 and ipv6 """
    if not valid_string(addr):
        return False
    try:
        socket.inet.pton(addr)
    except AttributeError:
        try:
            socket.inet_aton(addr)
        except socket.error:
            return False
        return addr.count('.') == 3
    except socket.error:
        return False

    return True

def is_dns(to_be_checked: str) -> bool:
    if not valid_string(to_be_checked):
        return False
    valid = re.match(
        r"^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$"\
        , to_be_checked)
    return True if valid else False


def get_cert_san(cert):
    """ return subject alternate name as a string """
    ext_count = cert.get_extension_count()
    if not ext_count:
        return 87  # ERROR_INVALID_PARAMETER

    san = ''
    for i in range(ext_count):
        ext = cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = str(ext)

    return san if san != '' else 87

def check_for_ip_addr(san):
    """ return list of strings that can be IP """
    ip_addr = filter(is_ip_address, san)
    return ip_addr

def check_for_dns(san):
    """ return filter of strings that can be DNS """
    dns = filter(is_dns, san)
    return dns


def parse_vals(cert):
    """ Return list containing CN, list of IP addresses, DNS names """

    cert_cn = get_cert_cn(cert)
    if cert_cn == 123:  # ERROR_INVALID_NAME
        return 123

    cert_vals = []
    cert_vals.append(cert_cn)

    san_extension = get_cert_san(cert)
    if any(san_extension == x for x in [87]):
        return san_extension

    sanitized_san = san_extension.replace('DNS:', '')
    sanitized_san = sanitized_san.replace('IP:', '')
    comma_seperated_vals = sanitized_san.split(', ')

    ip_addresses = list(check_for_ip_addr(comma_seperated_vals))
    if ip_addresses == "":
        ip_addresses = None
    cert_vals.append(ip_addresses)

    dns_names = list(check_for_dns(comma_seperated_vals))
    if dns_names == "":
        dns_names = None
    cert_vals.append(dns_names)

    return cert_vals

def get_x509_from_file(file_name: str):
    """ Read a text file and returns a X509 certificate object """

    try:
        with open(file_name, 'r') as cert_file:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
            if cert == None:
                return 1006  # ERROR_FILE_INVALID

            return cert  # return cert if it's valid

    except:
        return 2  # ERROR_FILE_NOT_FOUND

def get_cert_san_name(file_name: str):
    if not valid_string(file_name):
        return 87  # ERROR_INVALID_PARAMETER

    cert = get_x509_from_file(file_name)
    if any(cert == x for x in [1006, 2]):
        return cert

     return parse_vals(cert)

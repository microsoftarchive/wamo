import OpenSSL.crypto
import base64
import os
import tempfile
import xml.dom.minidom

class PublishSettings:
    """Class to represent a Windows Azure .publishsettings file"""
    sub_id = None
    pkcs12_buf = None
    
    def __init__(self, ps):
        """Parse the file and save the info"""
        ps_doc = xml.dom.minidom.parse(ps)
        publish_data = ps_doc.getElementsByTagName('PublishData')[0]
        publish_profile = publish_data.getElementsByTagName('PublishProfile')[0]
        pkcs12_b64 = publish_profile.getAttribute('ManagementCertificate')
        sub = publish_profile.getElementsByTagName('Subscription')[0]
        self.sub_id = sub.getAttribute('Id')
        self.pkcs12_buf = base64.b64decode(pkcs12_b64)

    def write_pem(self, location = None):
        """Write the management certificate to a .pem file, either temporary or specified"""
        pkcs12 = OpenSSL.crypto.load_pkcs12(self.pkcs12_buf)
        cert = pkcs12.get_certificate()
        private_key = pkcs12.get_privatekey()
        cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key)
        pem_file = None
        if location is None:
            (pem_fd, location) = tempfile.mkstemp()
            pem_file = os.fdopen(pem_fd, 'w')
        else:
            #open location
            raise NotImplementedError
        pem_file.write(pkey_pem)
        pem_file.write(cert_pem)
        pem_file.close
        return location

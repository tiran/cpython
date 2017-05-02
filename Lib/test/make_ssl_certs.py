"""Make the custom certificate and private key files used by test_ssl
and friends."""

import glob
import os
import shutil
import tempfile
from subprocess import *

req_template = """
    [req]
    distinguished_name     = {dn}
    x509_extensions        = {ext}
    prompt                 = no
    default_bits           = 2048
    default_md             = sha256
    utf8                   = yes
    string_mask            = utf8only

    [req_distinguished_name]
    C                      = XY
    L                      = Castle Anthrax
    O                      = Python Software Foundation
    CN                     = {cn}

    [leaf_extensions]
    subjectAltName         = @san
    keyUsage               = critical,digitalSignature,keyEncipherment
    extendedKeyUsage       = serverAuth,clientAuth
    subjectKeyIdentifier   = hash
    authorityKeyIdentifier = keyid:always
    basicConstraints       = CA:false

    [selfsigned_extensions]
    subjectAltName         = @san

    [san]
    DNS.1 = {hostname}
    {extra_sans}

    [dir_sect]
    C                      = XY
    L                      = Castle Anthrax
    O                      = Python Software Foundation
    CN                     = dirname example

    [princ_name]
    realm = EXP:0, GeneralString:KERBEROS.REALM
    principal_name = EXP:1, SEQUENCE:principal_seq

    [principal_seq]
    name_type = EXP:0, INTEGER:1
    name_string = EXP:1, SEQUENCE:principals

    [principals]
    princ1 = GeneralString:username

    [ca_distinguished_name]
    C                      = XY
    L                      = Castle Anthrax
    O                      = Python Software Foundation CA
    CN                     = our-ca-server

    [ca_extensions]
    keyUsage               = critical,keyCertSign,cRLSign
    subjectKeyIdentifier   = hash
    authorityKeyIdentifier = keyid:always
    basicConstraints       = CA:true

    [ca]
    default_ca             = CA_default

    [CA_default]
    dir                    = cadir
    database               = $dir/index.txt
    crlnumber              = $dir/crl.txt
    default_md             = sha256
    default_days           = 3600
    default_crl_days       = 3600
    name_opt               = multiline,-esc_msb,utf8
    certificate            = pycacert.pem
    private_key            = pycakey.pem
    serial                 = $dir/serial
    RANDFILE               = $dir/.rand
    policy                 = policy_anything

    [policy_anything]
    countryName             = optional
    stateOrProvinceName     = optional
    localityName            = optional
    organizationName        = optional
    organizationalUnitName  = optional
    commonName              = supplied
    emailAddress            = optional
    """

here = os.path.abspath(os.path.dirname(__file__))


def make_cert_key(hostname, sign=False, ext='leaf_extensions',
                  extra_sans=(), cn=None):
    print("creating cert for " + hostname)
    tempnames = []
    for i in range(3):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tempnames.append(f.name)
    req_file, cert_file, key_file = tempnames

    params = dict(
        hostname=hostname,
        cn=cn if cn is not None else hostname,
        extra_sans='\n'.join(extra_sans),
        ext=ext,
        dn='req_distinguished_name',
    )

    try:
        req = req_template.format(**params)
        with open(req_file, 'w') as f:
            f.write(req)
        args = ['req', '-new', '-days', '3650', '-nodes',
                '-newkey', 'rsa:2048', '-keyout', key_file,
                '-config', req_file]
        if sign:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                tempnames.append(f.name)
                reqfile = f.name
            args += ['-out', reqfile ]

        else:
            args += ['-x509', '-out', cert_file ]
        check_call(['openssl'] + args)

        if sign:
            args = ['ca', '-config', req_file, '-out', cert_file, '-outdir', 'cadir',
                    '-policy', 'policy_anything', '-extensions', ext,
                    '-batch', '-infiles', reqfile ]
            check_call(['openssl'] + args)


        with open(cert_file, 'r') as f:
            cert = f.read()
        with open(key_file, 'r') as f:
            key = f.read()
        return cert, key
    finally:
        for name in tempnames:
            os.remove(name)


TMP_CADIR = 'cadir'


def unmake_ca():
    shutil.rmtree(TMP_CADIR)


def make_ca():
    if os.path.isdir(TMP_CADIR):
        unmake_ca()
    os.mkdir(TMP_CADIR)

    with open(os.path.join('cadir','index.txt'),'a+') as f:
        pass # empty file
    with open(os.path.join('cadir','crl.txt'),'a+') as f:
        f.write("00")
    with open(os.path.join('cadir','index.txt.attr'),'w+') as f:
        f.write('unique_subject = no')

    params = dict(
        hostname='',
        cn=None,
        extra_sans='',
        ext='ca_extensions',
        dn='ca_distinguished_name',
    )

    with tempfile.NamedTemporaryFile("w") as t:
        t.write(req_template.format(**params))
        t.flush()
        with tempfile.NamedTemporaryFile() as f:
            args = ['req', '-config', t.name, '-new', '-days', '3650', '-nodes',
                    '-newkey', 'rsa:2048', '-keyout', 'pycakey.pem',
                    '-out', f.name]
            check_call(['openssl'] + args)
            args = ['ca', '-config', t.name, '-create_serial',
                    '-out', 'pycacert.pem', '-batch', '-outdir', TMP_CADIR,
                    '-keyfile', 'pycakey.pem', '-days', '3650',
                    '-extensions', 'ca_extensions',
                    '-selfsign', '-infiles', f.name ]
            check_call(['openssl'] + args)
            args = ['ca', '-config', t.name, '-gencrl', '-out', 'revocation.crl']
            check_call(['openssl'] + args)


def rehash():
    capath = os.path.join(here, 'capath')

    # remove existing hash files
    for name in glob.glob(os.path.join(capath, '*.?')):
        os.unlink(name)

    # copy pycacert.pem without header
    args = ['x509', '-in', os.path.join(here, 'pycacert.pem'),
            '-out', os.path.join(capath, 'pycacert.pem')]
    check_output(['openssl'] + args)

    # new hashes
    check_output(['c_rehash', '-v', capath])
    # old hashes with no delete
    check_output(['c_rehash', '-v', '-n', '-old', capath])

    # replace symlinks with files
    for hashfile in glob.glob(os.path.join(capath, '*.?')):
        orig = os.readlink(hashfile)
        orig = os.path.join(os.path.dirname(hashfile), orig)
        os.unlink(hashfile)
        shutil.copyfile(orig, hashfile)


if __name__ == '__main__':
    os.chdir(here)
    cert, key = make_cert_key('localhost', ext='selfsigned_extensions')
    with open('ssl_cert.pem', 'w') as f:
        f.write(cert)
    with open('ssl_key.pem', 'w') as f:
        f.write(key)
    print("password protecting ssl_key.pem in ssl_key.passwd.pem")
    check_call(['openssl','rsa','-in','ssl_key.pem','-out','ssl_key.passwd.pem','-des3','-passout','pass:somepass'])
    check_call(['openssl','rsa','-in','ssl_key.pem','-out','keycert.passwd.pem','-des3','-passout','pass:somepass'])

    with open('keycert.pem', 'w') as f:
        f.write(key)
        f.write(cert)

    with open('keycert.passwd.pem', 'a+') as f:
        f.write(cert)

    # For certificate matching tests
    make_ca()
    cert, key = make_cert_key('fakehostname')
    with open('keycert2.pem', 'w') as f:
        f.write(key)
        f.write(cert)

    cert, key = make_cert_key('localhost', True)
    with open('keycert3.pem', 'w') as f:
        f.write(key)
        f.write(cert)
    #with open('keycert3_cert.pem', 'w') as f:
    #    f.write(cert)
    #with open('keycert3_key.pem', 'w') as f:
    #    f.write(key)
    #check_call([
    #    'openssl', 'rsa', '-in', 'keycert3_key.pem',
    #    '-out', 'keycert3_key.passwd.pem', '-des3', '-passout', 'pass:somepass'
    #])

    cert, key = make_cert_key('fakehostname', True)
    with open('keycert4.pem', 'w') as f:
        f.write(key)
        f.write(cert)

    extra_sans = ['IP.1 = 127.0.0.1', 'IP.2 = ::1', ]
    cert, key = make_cert_key('localhost', True,  cn='SAN only',
                              extra_sans=extra_sans)
    with open('sanonly.pem', 'w') as f:
        f.write(key)
        f.write(cert)

    extra_sans = [
        'otherName.1 = 1.2.3.4;UTF8:some other identifier',
        'otherName.2 = 1.3.6.1.5.2.2;SEQUENCE:princ_name',
        'email.1 = user@example.org',
        'DNS.2 = www.example.org',
        # GEN_X400
        'dirName.1 = dir_sect',
        # GEN_EDIPARTY
        'URI.1 = https://www.python.org/',
        'IP.1 = 127.0.0.1',
        'IP.2 = ::1',
        'RID.1 = 1.2.3.4.5',
    ]

    cert, key = make_cert_key('allsans', extra_sans=extra_sans)
    with open('allsans.pem', 'w') as f:
        f.write(key)
        f.write(cert)

    rehash()
    unmake_ca()

    print("\n\nPlease change the values in Lib/test/support/__init__.py")
    out = check_output([
        'openssl', 'x509', '-in', 'keycert3.pem', '-dates', '-serial', '-noout'
    ])
    out = out.decode('ascii').strip()
    for line in out.split('\n'):
        k, v = line.split('=', 1)
        print("CERT_{0} = '{1}'".format(k.upper(), v))

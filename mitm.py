import os
import tempfile
from twisted.internet import utils


def certMaker(cert):

    print('certMaker(%s)' % cert)

    if cert['subject'][-1][0][0] != 'commonName':
        raise Exception('tip of subject is not commonName')

    hostname = cert['subject'][-1][0][1]
    chash = cert['hash']

    keyfile = '%s-key.pem' % (chash,)
    csrfile = '%s-csr.pem' % (chash,)
    certfile = '%s-crt.pem' % (chash,)

    try:
        # check for a cert already on-disk
        # with the same sha1 hash of binary blob
        os.stat(certfile)
    except:
        print("making new fake cert")
    else:
        print("using fake cert from disk")
        # file already exists on-disk
        # assume key is present too
        r = {
                'name': hostname,
                'cert': certfile,
                'key': keyfile,
            }
        return r


    # Is this sufficient? Maybe we want to copy whole DN?
    # Or read the 2nd & subsequent bits of the DN from our CA cert?
    subj = '/CN=%s/OU=FakeCA/O=My Fake CA' % hostname

    # FIXME: key filenames by host/port combo, or maybe "real" cert hash?
    # FIXME: make the CA configurable?
    res = yield utils.getProcessOutputAndValue(
        '/usr/bin/openssl',
        (
            'req',
            '-newkey',
            'rsa:1024',
            '-nodes',
            '-subj',
            subj,
            '-keyout',
            keyfile,
            '-out',
            csrfile
        ),
    )

    out, err, code = res
    if code!=0:
        raise Exception('error generating csr', err)

    fd, tmpname = tempfile.mkstemp()
    try:
        ext = os.fdopen(fd, 'w')

        # write the subjectAltName extension into a temp .cnf file
        dns = []
        if 'subjectAltName' in cert:
            for san in cert['subjectAltName']:
                if san[0]!='DNS':
                    continue
                dns.append('DNS:'+san[1])
        if dns:
            print(ext, "subjectAltName=" + ','.join(dns))

        # FIXME: copy other extensions? eku?
        ext.close()

        # process the .csr with our CA cert to generate a signed cert
        res = yield utils.getProcessOutputAndValue(
            '/usr/bin/openssl',
            (
                'x509',
                '-req',
                '-days',
                '365',
                '-in',
                csrfile,
                '-CA',
                'ca.crt',
                '-CAkey',
                'ca.key',
                '-set_serial',
                '0',
                '-extfile',
                tmpname,
                '-out',
                certfile),
            )
    finally:
        # remove temp file
        os.unlink(tmpname)

    out, err, code = res
    if code==0:
        r = {
                'name': hostname,
                'cert': certfile,
                'key': keyfile,
                }
        return r

    raise Exception('failed to generate cert', err)
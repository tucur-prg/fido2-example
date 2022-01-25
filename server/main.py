from fastapi import FastAPI, Form
from starlette.middleware.cors import CORSMiddleware

import uvicorn
import logging
from base64 import urlsafe_b64decode, urlsafe_b64encode
import json
import cbor2
import hashlib
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger('uvicorn')

def decode(str):
    str = str + '=' * (-len(str)%4)
    return urlsafe_b64decode(str)

def jwk(pk):
    if pk[3] == -7:
        pkjwk = {
            'kty': 'EC',
            'crv': 'P-256',
            'x': urlsafe_b64encode(pk[-2]).decode(),
            'y': urlsafe_b64encode(pk[-3]).decode(),
        };
    elif pk[3] == -257:
        pkjwk = {
            'kty': 'RSA',
            'n': urlsafe_b64encode(pk[-1]).decode(),
            'e': urlsafe_b64encode(pk[-2]).decode(),
        };
    else:
        raise ValueError('Non algorithm.');

    return pkjwk;

def aaguid(id):
    return id[0:8] + '-' + id[8:12] + '-' + id[12:16] + '-' + id[16:]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
)

@app.get("/health")
async def health():
    return {"text": "OK"}

@app.post("/regist")
async def regist(
    id = Form(...),
    attestationObject = Form(...),
    clientDataJSON = Form(...),
):
    logger.info("call regist")
    logger.info(id)
    logger.info(attestationObject)
    logger.info(clientDataJSON)

    attestation = cbor2.loads(decode(attestationObject))
    clientData = json.loads(decode(clientDataJSON))

    logger.info(attestation)
    logger.info(clientData)

#    challenge = urlsafe_b64encode(bytearray('my_challenge', encoding='utf-16le'))
#    logger.info("{}".format(challenge))
    # DBに登録してある物と比較検証する SELECT userId Where challenge
    logger.info("challenge: {}".format(decode(clientData['challenge']).decode()))

    # rpIdHash
    logger.info("rpIdHash: {}".format(attestation['authData'][0:32].hex()))
#    logger.info(hashlib.sha256(b'localhost').hexdigest())

    # flags
    flags = attestation['authData'][32]
    logger.info("flags: {}".format(flags))
    logger.info(bool(flags & 0x01)) # UP == true
    logger.info(bool(flags & 0x04)) # UV == true

    # signCount
    signCount = attestation['authData'][33] << 24 | attestation['authData'][34] << 16 | attestation['authData'][35] << 8 | attestation['authData'][36]
    logger.info("signCount: {}".format(signCount))

    # aaguid
    logger.info("aaguid: {}".format(aaguid(attestation['authData'][37:53].hex())))

    credentialIdLength = (attestation['authData'][53] << 8) + attestation['authData'][54]
    credentialId = attestation['authData'][55:55+credentialIdLength]
    credentialPublicKey = attestation['authData'][55+credentialIdLength:]

    logger.info(len(credentialId))
    logger.info(credentialId.hex())
    logger.info(len(credentialPublicKey))
    logger.info(cbor2.loads(credentialPublicKey))
    logger.info(jwk(cbor2.loads(credentialPublicKey)))

    logger.info(attestation['fmt'])
    if attestation['fmt'] == 'packed':
        if 'x5c' in attestation['attStmt']:
            signature = attestation['attStmt']['sig']
            attestnCert = attestation['attStmt']['x5c'][0]

            cert = x509.load_der_x509_certificate(attestnCert, default_backend())
#            logger.info(cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME))

            pn = cert.public_key().public_numbers()
            clientDataHash = hashlib.sha256(decode(clientDataJSON)).digest()
            message = attestation['authData'] + clientDataHash

            try:
                logger.info(pn.x)
                logger.info(pn.y)

                ec.EllipticCurvePublicNumbers(pn.x, pn.y, ec.SECP256R1()) \
                .public_key(default_backend()) \
                .verify(signature, message, ec.ECDSA(hashes.SHA256()))
            except:
                return {"error": "Invalid Signature"}

    '''
    id, jwk(credentialPublicKey), signCount を保存
    '''
    saveData = {
        'id': id,
        'jwk': jwk(cbor2.loads(credentialPublicKey)),
        'count': signCount,
        'time': time.time(),
    }

    # hex(rawId)
    logger.info(decode(id).hex())
    logger.info(saveData)

    with open('/tmp/hogehoge.json', mode='w') as f:
        f.write(json.dumps(saveData))

    return saveData

@app.post("/auth")
async def auth(
    id = Form(...),
    authenticatorData = Form(...),
    clientDataJSON = Form(...),
    signature = Form(...),
):
    logger.info("call auth")
    logger.info(authenticatorData)
    logger.info(clientDataJSON)
    logger.info(signature)

    authenticator = decode(authenticatorData)
    clientData = json.loads(decode(clientDataJSON))
    sign = decode(signature)

    logger.info(authenticator)
    logger.info(clientData)
    logger.info(sign)

    logger.info("challenge: {}".format(decode(clientData['challenge']).decode()))

    # rdIdHash
    logger.info("rpIdHash: {}".format(authenticator[0:32].hex()))

    # flags
    flags = authenticator[32]
    logger.info("flags: {}".format(flags))
    logger.info(bool(flags & 0x01)) # UP == true
    logger.info(bool(flags & 0x04)) # UV == true

    # signCount
    signCount = authenticator[33] << 24 | authenticator[34] << 16 | authenticator[35] << 8 | authenticator[36]
    logger.info("signCount: {}".format(signCount))
    logger.info(authenticator[33])
    logger.info(authenticator[34])
    logger.info(authenticator[35])
    logger.info(authenticator[36])

    # saveData を取ってくる
    with open('/tmp/hogehoge.json') as f:
        loadData = json.loads(f.read())

    logger.info(loadData)

    clientDataHash = hashlib.sha256(decode(clientDataJSON)).digest()
    message = authenticator + clientDataHash

    try:
        # kty == EC の場合の処理
        x = decode(loadData['jwk']['x'])
        y = decode(loadData['jwk']['y'])

        x = int(x.hex(), 16)
        y = int(y.hex(), 16)

        '''
        crv == 'P-256': ec.SECP256R1()
        crv == 'P-384': ec.SECP384R1()
        crv == 'P-521': ec.SECP521R1()
        '''
        ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()) \
        .public_key(default_backend()) \
        .verify(sign, message, ec.ECDSA(hashes.SHA256()))
    except:
        return {"error": "Invalid Signature"}

    logger.info("checkCount: {} > {}".format(signCount, loadData['count']))
    if signCount <= loadData['count']:
        return {"error": "Invalid Sign Count"}

    # カウンターを進めるて保存
    loadData['count'] = signCount
    with open('/tmp/hogehoge.json', mode='w') as f:
        f.write(json.dumps(loadData))

    # 認証処理

    return {
        "text":"OK",
        "user":"hogehoge",
        "session":"******",
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        reload=True,
        port=8080,
        debug=True,
    )

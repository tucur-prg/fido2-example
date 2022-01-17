from fastapi import FastAPI, Form
from starlette.middleware.cors import CORSMiddleware

import logging

from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import (
    AttestationConveyancePreference,
    UserVerificationRequirement,
    AuthenticatorAttachment
)

from base64 import urlsafe_b64decode, urlsafe_b64encode
import pickle
import cbor2
import os

logger = logging.getLogger('uvicorn')

# API Server
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
)

# FIDO Server
rp = PublicKeyCredentialRpEntity("localhost", "WebAuthn Test")
server = Fido2Server(
    rp,
    AttestationConveyancePreference.DIRECT,
)

# Methods
def decode(str):
    str = str + '=' * (-len(str)%4)
    return urlsafe_b64decode(str)

# Routes
@app.get("/health")
async def health():
    return {"text": "OK"}

@app.get("/regist")
async def get_regist():
    if os.path.exists('/tmp/user.bin'):
        with open('/tmp/user.bin') as f:
            s = decode(f.read())

        credentials = (pickle.loads(s), )
    else:
        credentials = None

    try:
        # navigator.credentials.create に渡す options
        res = server.register_begin(
            {
                'id': "hogehoge".encode('utf-8'),
                'name': "webauthn@example.com",
                'displayName': "Hoge",
            },
            credentials,
            resident_key = True,
            user_verification = UserVerificationRequirement.REQUIRED,
            authenticator_attachment = AuthenticatorAttachment.PLATFORM,
            challenge = bytes('my_challenge', encoding='utf-16le'),
        )

        # res[1] の値が register_complete の state に当たるので保存して登録時に呼び出す
    except BaseException as e:
        import traceback
        logger.info(traceback.format_exc())
        return {"error": str(e)}

    return {"options": urlsafe_b64encode(cbor2.dumps(res[0]))}

@app.post("/regist")
async def post_regist(
    id = Form(...),
    attestationObject = Form(...),
    clientDataJSON = Form(...),
):
    state = {
        "challenge": urlsafe_b64encode(bytearray('my_challenge', encoding='utf-16le')),
        "user_verification": UserVerificationRequirement.REQUIRED,
    }
    attestation = AttestationObject(decode(attestationObject))
    clientData = ClientData(decode(clientDataJSON))

    try:
        authData = server.register_complete(
            state,
            clientData,
            attestation,
        )
    except BaseException as e:
        import traceback
        logger.info(traceback.format_exc())
        return {"error": str(e)}

    saveData = urlsafe_b64encode(pickle.dumps(authData.credential_data))

    with open('/tmp/user.bin', mode='w') as f:
        f.write(saveData.decode())

    return {"text":"OK"}

@app.get("/auth")
async def get_auth():
    with open('/tmp/user.bin') as f:
        s = decode(f.read())

    credentials = (pickle.loads(s), )

    try:
        # navigator.credentials.get に渡す options
        res = server.authenticate_begin(
            credentials,
            UserVerificationRequirement.REQUIRED,
            bytes('my_challenge', encoding='utf-16le'),
        )

        # res[1] の値が authenticate_complete の state に当たるので保存して認証時に呼び出す
    except BaseException as e:
        import traceback
        logger.info(traceback.format_exc())
        return {"error": str(e)}

    return {"options": urlsafe_b64encode(cbor2.dumps(res[0]))}

@app.post("/auth")
async def post_auth(
    id = Form(...),
    authenticatorData = Form(...),
    clientDataJSON = Form(...),
    signature = Form(...),
):
    state = {
        "challenge": urlsafe_b64encode(bytearray('my_challenge', encoding='utf-16le')),
        "user_verification": UserVerificationRequirement.REQUIRED,
    }
    credential_id = decode(id)
    authenticator = AuthenticatorData(decode(authenticatorData))
    clientData = ClientData(decode(clientDataJSON))
    sign = decode(signature)

    with open('/tmp/user.bin') as f:
        s = decode(f.read())

    credentials = (pickle.loads(s), )

    try:
        server.authenticate_complete(
            state,
            credentials,
            credential_id,
            clientData,
            authenticator,
            sign,
        )
    except BaseException as e:
        import traceback
        logger.info(traceback.format_exc())
        return {"error": str(e)}

    return {
        "text": "OK",
        "user": "hogehoge",
        "session": "****",
    }

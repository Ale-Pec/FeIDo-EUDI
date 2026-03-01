/*
 * Copyright (C) 2024-2026 Alessandro
 * 
 * This file is part of a Master's Thesis project.
 * Based on or modified from the original FeIDo Browser Extension.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; version 2.1 of the License.
 */

// build the needed credentials.create or credentials.get protobuf 
async function buildCredentials(msg) {
    if (msg.type == "credentials.create") {
        return buildCredentialsCreate(msg.opts.publicKey, msg.origin);
    } 
    else if (msg.type == "credentials.get"){
        return buildCredentialsRequest(msg.opts.publicKey, msg.origin);
    }
    else {
        console.log("Message not of credentials.create or credentials.get type!");
    }
}

// build a credentials.create protobuf from an intercepted browser FIDO request
async function buildCredentialsCreate(msg, orig) {
    //let root = await protobuf.load("FEIDOProto.proto");
    let root = await protobuf.load("FEIDOProto.json");
    
    // Obtain a message type
    var FEIDOPacket = root.lookupType("de.cispa.feido.FEIDOWrapper");


    console.log("Challenge: " + msg.challenge);
    // Exemplary payload
    var wrapper = {
        publicKeyCredentialCreationOptions: {
            origin: orig,
            challenge: msg.challenge,
            rp: {
                id: msg.rp.id
            },
            user: {
                id: msg.user.id,
                displayName: msg.user.displayName
            },
            pubKeyCredParams: {
                type: msg.pubKeyCredParams[0].type,
                alg: msg.pubKeyCredParams[0].alg
            }
        }
        }

    // Verify the payload if necessary (i.e. when possibly incomplete or invalid)
    var errMsg1 = FEIDOPacket.verify(wrapper);
    if (errMsg1)
        throw Error(errMsg1);

    // Create a new message
    var message = FEIDOPacket.create(wrapper); // or use .fromObject if conversion is necessary

    // Encode a message to an Uint8Array (browser) or Buffer (node)
    buffer = FEIDOPacket.encode(message).finish();
    console.log(buffer);

    let test = FEIDOPacket.decode(buffer);
    console.log(test);

    return buffer;
}

// build a credentials.request protobuf from an intercepted browser FIDO request
async function buildCredentialsRequest(msg, orig) {
    //let root = await protobuf.load("FEIDOProto.proto");
    let root = await protobuf.load("FEIDOProto.json");
    
    // Obtain a message type
    var FEIDOPacket = root.lookupType("de.cispa.feido.FEIDOWrapper");


    console.log("Challenge: " + msg.challenge);
    // Exemplary payload
    var wrapper = {
        publicKeyCredentialRequestOptions: {
            origin: orig,
            rpId: msg.rpId,
            challenge:  msg.challenge
        }
    }

    // Verify the payload if necessary (i.e. when possibly incomplete or invalid)
    var errMsg1 = FEIDOPacket.verify(wrapper);
    if (errMsg1)
        throw Error(errMsg1);

    // Create a new message
    var message = FEIDOPacket.create(wrapper); // or use .fromObject if conversion is necessary

    // Encode a message to an Uint8Array (browser) or Buffer (node)
    buffer = FEIDOPacket.encode(message).finish();
    console.log(buffer);

    let test = FEIDOPacket.decode(buffer);
    console.log(test);

    return buffer;
}

async function parseReturn(buffer, flow = 'registration') {
    const metaForSub = { substep: true };
    let arrayBuff = FeidoMetrics ? await FeidoMetrics.measureAsync(`${flow}.forwardToContent.parseReturn.arrayBuffer`, () => buffer.data.arrayBuffer(), metaForSub) : await buffer.data.arrayBuffer();
    let uint8Arr = new Uint8Array(arrayBuff);


    //let root = await protobuf.load("FEIDOProto.proto");
    let root = FeidoMetrics ? await FeidoMetrics.measureAsync(`${flow}.forwardToContent.parseReturn.protobufLoad`, () => protobuf.load("FEIDOProto.json"), metaForSub) : await protobuf.load("FEIDOProto.json");
    
    // Obtain a message type
    var FEIDOPacket = root.lookupType("de.cispa.feido.FEIDOWrapper");

    // Decode message
    let message;
    try {
        message = FeidoMetrics ? FeidoMetrics.measureSync(`${flow}.forwardToContent.parseReturn.protobufDecode`, () => FEIDOPacket.decode(uint8Arr), metaForSub) : FEIDOPacket.decode(uint8Arr);
        console.log("Decoded protobuf: " + message);
    } catch (e) {
        if (e instanceof protobuf.util.ProtocolError) {
            console.log("Could only decode partial returned protobuf message!");
          } else {
            console.log("Could not decode returned message!");
          }
    }
    
    // Sanity check
    if (message.publicKeyCredential == null){
        console.log("Returned protobuf message not of publicKeyCredential type!");
    }

    // Check if Attestation or AssertionResponse
    let response;
    if (message.publicKeyCredential.response.authenticatorAttestationResponse){
        response = new AuthenticatorAttestationResponse(
            message.publicKeyCredential.response.authenticatorAttestationResponse.clientDataJSON,
            message.publicKeyCredential.response.authenticatorAttestationResponse.attestationObject);

    }
    else if (message.publicKeyCredential.response.authenticatorAssertionResponse){
        response = new AuthenticatorAssertionResponse(
            message.publicKeyCredential.response.authenticatorAssertionResponse.clientDataJSON,
            message.publicKeyCredential.response.authenticatorAssertionResponse.authenticatorData,
            message.publicKeyCredential.response.authenticatorAssertionResponse.signature,
            message.publicKeyCredential.response.authenticatorAssertionResponse.userHandle);
    }

    // Create WebAuthn compatible PublicKeyCredential
    let publicKeyCredential = new PublicKeyCredential(
        message.publicKeyCredential.rawId,
        response,
        "cross-platform");

    return publicKeyCredential;
}

// Build a FEIDOWrapper containing a PublicKeyCredential with an AttestationResponse
// rawId, clientDataJSON, attestationObject are Uint8Array or ArrayBuffer
async function buildAttestationReturn(rawId, clientDataJSON, attestationObject) {
    const metaForSub = { substep: true };
    // Ensure Uint8Array
    const toUint8 = (x) => (x instanceof Uint8Array ? x : new Uint8Array(x));
    const rawIdU8 = toUint8(rawId);
    const cdjU8 = toUint8(clientDataJSON);
    const attObjU8 = toUint8(attestationObject);

    let root = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.buildResponse.protobufLoad', () => protobuf.load("FEIDOProto.json"), metaForSub) : await protobuf.load("FEIDOProto.json");
    var FEIDOPacket = root.lookupType("de.cispa.feido.FEIDOWrapper");

    const wrapper = {
        publicKeyCredential: {
            rawId: rawIdU8,
            response: {
                authenticatorAttestationResponse: {
                    clientDataJSON: cdjU8,
                    attestationObject: attObjU8,
                }
            },
            authenticatorAttachment: { type: "cross-platform" }
        }
    };

    const err = FeidoMetrics ? FeidoMetrics.measureSync('registration.buildResponse.protobufVerify', () => FEIDOPacket.verify(wrapper), metaForSub) : FEIDOPacket.verify(wrapper);
    if (err) throw Error(err);
    const message = FeidoMetrics ? FeidoMetrics.measureSync('registration.buildResponse.protobufCreate', () => FEIDOPacket.create(wrapper), metaForSub) : FEIDOPacket.create(wrapper);
    return FeidoMetrics ? FeidoMetrics.measureSync('registration.buildResponse.protobufEncode', () => FEIDOPacket.encode(message).finish(), metaForSub) : FEIDOPacket.encode(message).finish();
}

// Build a FEIDOWrapper containing a PublicKeyCredential with an AssertionResponse
// rawId, clientDataJSON, authenticatorData, signature, userHandle are Uint8Array or ArrayBuffer
async function buildAssertionReturn(rawId, clientDataJSON, authenticatorData, signature, userHandle) {
    const toUint8 = (x) => (x instanceof Uint8Array ? x : new Uint8Array(x || []));
    const rawIdU8 = toUint8(rawId);
    const cdjU8 = toUint8(clientDataJSON);
    const authDataU8 = toUint8(authenticatorData);
    const sigU8 = toUint8(signature);
    const uhU8 = toUint8(userHandle);

    let root = await protobuf.load("FEIDOProto.json");
    var FEIDOPacket = root.lookupType("de.cispa.feido.FEIDOWrapper");

    const wrapper = {
        publicKeyCredential: {
            rawId: rawIdU8,
            response: {
                authenticatorAssertionResponse: {
                    clientDataJSON: cdjU8,
                    authenticatorData: authDataU8,
                    signature: sigU8,
                    userHandle: uhU8,
                }
            },
            authenticatorAttachment: { type: "cross-platform" }
        }
    };

    const err = FEIDOPacket.verify(wrapper);
    if (err) throw Error(err);
    const message = FEIDOPacket.create(wrapper);
    return FEIDOPacket.encode(message).finish();
}

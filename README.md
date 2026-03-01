# Master's Thesis Project

**This repository contains the code developed for my Master's Thesis.**

The project extends and is based on the original **FeIDo: Recoverable FIDO2 Tokens Using Electronic IDs** research project, whose details and original documentation are provided below.

---

# FeIDo: Recoverable FIDO2 Tokens Using Electronic IDs
This is the umbrella repository of the FeIDo research project.
The goal of FeIDo is to provide a virtual FIDO2 authenticator that does not incur extra costs and tackles the problem of account recovery on a token loss.
FeIDo introduces the concept of attribute-based FIDO2 credentials using eIDs and TEEs.
The corresponding research paper has been accepted for [CCS 2022](https://www.sigsac.org/ccs/CCS2022/) and will be published as part of the proceedings (probably in Nov 2022).

The author's version of the paper is provided for private use in the CISPA database: https://publications.cispa.saarland/3765/

## Repo Note
Please clone this repository in order to build all FeIDo subcomponents (instead of cloning subrepos directly), because the subrepos use symbolic links to access the shared protobuf files provided by this umbrella repo.


## Directory structure
* `feido-browser-extension/`    -- FeIDo browser extension (Firefox)
    * `background.js`             -- logica principale: derivazione locale, cifratura, export/import
    * `pid_scraper.js`            -- content script: lettura attributi dal DOM del verificatore
    * `popup.html/.js`            -- UI per passphrase, lock/unlock, export/import
    * `publicKeyCredentialOverwrite.js` / `overwrite.js` / `protoBuilder.js` -- integrazione WebAuthn/Proto
    * `FEIDOProto.proto/.json`    -- schema protobuf condiviso

* `DIDs & VCs/`                 -- utilità e dati per DID/VC dimostrativi
    * `create-did.js`, `create-vc.js`, `derive-fido-from-vc.js`
    * `DIDs/`, `VCs/`, `PrivateKeys/`, `FIDO2/` (esempi e artefatti)

* `webauthn/`                   -- patch e demo locali per webauthn.io
    * `webauthn.io/`              -- sorgente demo (con patch)
    * `local-demo/`, `webauthn.patch`

* `package.json`                -- metadati/utility di progetto a livello root
* `README.md`                   -- questo file (overview + link alle sezioni di sicurezza)



## Build and Run Instructions Overview
In the following, we will provide an overview of the steps required to build an
run the FeIDo prototype.
Please refer to the README files of each subcomponent for detailed build and run
instructions of the respective FeIDo subcomponent.

1. Initialize and update all submodules:
    ```
    git submodule update --init
    ```


2. Build the Middleware Android app by following the instructions given in `feido-middleware-app/README.md`.

    Then run it on a connected smartphone *with NFC support*.
    The current protoype has been successfully tested on a `Samsung Galaxy S8` running `Android 9 (Pie)`.


3. Prepare and install the Firefox Browser extension by following the instruction given in `feido-browser-extension/README-md`.

    Security considerations and operational policies for the browser extension are documented in `feido-browser-extension/README.md` (see the "Security (overview)" section).


4. Prepare, configure, and build the Intel SGX Credential Service:

    Follow the build instructions given in `feido-credential-service/README.md`.
    Then run the `credservice-sgx` executable (also see specific README file).

5. Configure, build, and run the demo eID Revocation Database Service:

    Follow the build and run instructions given in `feido-database-server/README.md`.

6. Optionally: Follow the instructions in `webauthn/` to host the webauthn.io page
    locally (with time measurement patch).


7. Connect the Android app (FeIDo middleware) with your German ePassport:

    Input your ePassport's MRZ data into the Android app.
    Place your phone on to your ePassport to connect to it via NFC.
    When using a Galaxy S8, you put the whole phone centrally on your ePassport
    (i.e., the phone covers the whole ePassport).
    On success, the phone will vibrate and connect to your ePassport (check the
    log messages given in the status field of the app).

    The current prototype supports *only German ePassports* at the moment.


8. Perform the registration and login with your Firefox browser.

    Using your Firefox browser with loaded FeIDo extension, navigate to `webauthn.io`
    (or your locally hosted instance of it).
    Input a user name and hit `Register`.
    Wait for the output console in the Android app to stop, then hit `Login`.
    You should now be redirected to a "successful login" page.

    Warning: if hosting webautn.io locally, connect via `localhost`, not via IP
    (127.0.0.1), as this will currently cause a name mismatch error, shown in the
    webauthn.io log as:
    ```
    Expected: "localhost"
    Received: "127.0.0.1"
    ```


## Limitations
As described in the research paper, the FeIDo prototype does not yet implement anonymous credentials.


## License
The protobuf files in `protobuf` are licensed according to the subproject using it, i.e., under LGPL-2.1 when used by the browser extension and middleware app and under AGPL-3.0 when used by the credential service and database service.
Please check the license files of each subproject.

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
* `feido-browser-extension/`    -- FeIDo browser extension (Firefox) adapted for EDIW
    * `background.js`             -- Main logic for cryptographic derivation and processing
    * `popup.html/.js`            -- Extension user interface
    * `publicKeyCredentialOverwrite.js` / `overwrite.js` / `protoBuilder.js` -- WebAuthn integration
    * `FEIDOProto.proto/.json`    -- Protobuf schemas

* `package.json`                -- Dependencies and metadata
* `README.md`                   -- This file

## Build and Run Instructions

1. **Install Dependencies:**
   ```bash
   npm install
   ```

2. **Load Browser Extension:**
   * Open Firefox and go to `about:debugging#/runtime/this-firefox`
   * Click on "Load Temporary Add-on..."
   * Select any file (e.g., `manifest.json`) from the `feido-browser-extension/` directory.

## License
The browser extension code and protobuf files are licensed under **LGPL-2.1** as established by the original FeIDo repository. Modifications and adapters related to the EDIW infrastructure remain under the same license.
Please refer to the `LICENSE.txt` file within the sub-folders for detailed terms.

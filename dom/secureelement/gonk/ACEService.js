/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Copyright © 2015, Deutsche Telekom, Inc. */

"use strict";

const { classes: Cc, interfaces: Ci, utils: Cu } = Components;
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/Promise.jsm");
Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/Services.jsm");

XPCOMUtils.defineLazyModuleGetter(this, "DOMApplicationRegistry",
                                  "resource://gre/modules/Webapps.jsm");

XPCOMUtils.defineLazyModuleGetter(this, "SEUtils",
                                  "resource://gre/modules/SEUtils.jsm");

XPCOMUtils.defineLazyGetter(this, "SE", function() {
  let obj = {};
  Cu.import("resource://gre/modules/se_consts.js", obj);
  return obj;
});

let DEBUG = SE.DEBUG_ACE;
function debug(msg) {
  if (DEBUG) {
    dump("ACEservice: " + msg + "\n");
  }
}

/**
  * Implements decision making algorithm as described in GPD specification,
  * mostly in 3.1, 3.2 and 4.2.3.
  *
  * Since GPAccessRulesManager does not support APDU filters, decision making
  * algorithm does not support that either (should be straightforward to add
  * later, though).
  * TODO: Bug 1137533
  */
function GPAccessDecision(rules, certHash, aid) {
  this.rules = rules;
  this.certHash = certHash;
  this.aid = aid;
}

GPAccessDecision.prototype = {
  isAccessAllowed: function isAccessAllowed() {
    let decision = this.rules.some(this._decideAppAccess.bind(this));
    return decision;
  },

  _decideAppAccess: function _decideAppAccess(rule) {
    let appMatched, appletMatched, ruleAllows;

    // GPD 4.2.3 A and 4.2.3 C
    if (Array.isArray(rule.application)) {
      appMatched = this._applicationMatches(rule.application);
    // GPD 4.2.3 B and 4.2.3 D
    } else {
      appMatched = [Ci.nsIAccessRulesManager.ALLOW_ALL,
                    Ci.nsIAccessRulesManager.DENY_ALL]
                    .indexOf(rule.application) !== -1;
    }

    // GPD 4.2.3 A and 4.2.3 B
    if (Array.isArray(rule.applet)) {
      appletMatched = SEUtils.arraysEqual(rule.applet, this.aid);
    // GPD 4.2.3 C and 4.2.3 D
    } else {
      appletMatched = rule.applet === Ci.nsIAccessRulesManager.ALL_APPLET;
    }

    // Access is allowed, if rule does not deny access to an app.
    ruleAllows = rule.application !== Ci.nsIAccessRulesManager.DENY_ALL;

    return appMatched && appletMatched && ruleAllows;
  },

  _applicationMatches: function _applicationMatches(appArray) {
    if (!Array.isArray(appArray)) {
      return false;
    }

    return !!(appArray.find((hash) => {
      return SEUtils.arraysEqual(hash, this.certHash);
    }));
  }
};

function ACEService() {
  this._rulesManagers = new Map();

  this._rulesManagers.set(
    SE.TYPE_UICC,
    Cc["@mozilla.org/secureelement/access-control/rules-manager/gp;1"]
      .getService(Ci.nsIAccessRulesManager));

  this._rulesManagers.forEach((ruleManager, seType) => {
    ruleManager.init().then(() => {
      debug("Rules manager for '" + seType + "' SE initialised");
    });
  });
}

ACEService.prototype = {
  _rulesManagers: null,

  isAccessAllowed: function isAccessAllowed(localId, seType, aid) {
    let manifestURL = DOMApplicationRegistry.getManifestURLByLocalId(localId);
    if (!manifestURL) {
      return Promise.reject(new Error("Missing manifest for app: " + localId));
    }

    return new Promise((resolve, reject) => {
      debug("isAccessAllowed for " + manifestURL + " to " + aid);

      let devCert = this._getDevCertForApp(manifestURL);

      if (!devCert) {
        debug("App " + manifestURL + " tried to access SE, but no developer" +
                " certificate present");
        return reject(new Error("No developer certificate found"));
      }

      // TODO: Bug 973823
      //  - verify if app is signed by marketplace
      //  - retrieve the cert from the app
      //  - verify GUID signature
      //  - compute the hash of the cert and possibly store it for future use
      //    (right now we have the cert hash included in manifest file)
      //  - remove this once we have fixed all the todos
      //return manifest.secure_element_sig || "";
      return DOMApplicationRegistry.getManifestFor(manifestURL)
      .then((manifest) => {
        debug('manifest: ' + JSON.stringify(manifest));
        let guid_sig = SEUtils.hexStringToUint8Array(manifest.guid_sig);
        let guid = SEUtils.hexStringToUint8Array(manifest.guid);
        return this._checkSignature(devCert, guid_sig, guid);
      })
      .then((isSigValid) => {
         if (isSigValid) {
           return this._getSha1(cert);
         } else {
           return reject(new Error("App signature verification failed."))
         }
      })
      .then((certHash) => {
        if (!certHash) {
          return reject(new Error("No valid developer hash found"));
        }

        let rulesManager = this._rulesManagers.get(seType);
        if (!rulesManager) {
          debug("App " + manifestURL + " tried to access '" + seType + "' SE" +
                " which is not supported.");
          return reject(new Error("SE type '" + seType + "' not supported"));
        }

        rulesManager.getAccessRules()
        .then((rules) => {
          let decision = new GPAccessDecision(rules, certHash, aid);
          resolve(decision.isAccessAllowed());
        });
      })
      .catch(e => {
        debug('Exception at isAccessAllowed ' + e);
        resolve(false);
      });
    });

  },

  _getDevCertForApp: function _getDevCertForApp(manifestURL) {
    let app = DOMApplicationRegistry.getAppByManifestURL(manifestURL);

    if (!app) {
      throw Error("App not found.");
    }
    let appDir = null;
    // Pre-installed apps (if Non-engr builds)
    appDir = FileUtils.getDir("coreAppsDir", ["webapps", app.id], false, true);
    if (!appDir.exists()) {
      // Location for other apps, including Engr builds:
      appDir = FileUtils.getDir("webappsDir", ["webapps", app.id], false, true);
    }

    let appPackage = appDir.clone();
    appPackage.append("application.zip");

    let zipReader = Cc["@mozilla.org/libjar/zip-reader;1"]
      .createInstance(Ci.nsIZipReader);
    zipReader.open(appPackage);

    debug('has file: ' + zipReader.hasEntry("dev_cert.cer"));
    let devCertStream = zipReader.getInputStream("dev_cert.cer");
    let devCert = NetUtil.readInputStreamToString(devCertStream, devCertStream.available());
    devCert = SEUtils.hexStringToUint8Array(devCert);
    devCertStream.close();
    return devCert;
  },

  _checkSignature: function _checkSignature(devCert, guid_sig, guid) {
    let browserWindow = Services.wm.getMostRecentWindow("navigator:browser");
    let crypto = browserWindow.crypto;
    if (!crypto) {
      return Promise.reject(new Error("Browser is missing crypto support"));
    }
    if (!(devCert instanceof Uint8Array) ||
        !(guid_sig instanceof Uint8Array) ||
        !(guid instanceof Uint8Array)) {
      return Promise.reject(new Error("Certificate, guid signature, and guid" +
                            "all must be instances of Uint8Array"));
    }

    let alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" };
    return crypto.subtle.importKey("spki", devCert, alg, false, ['verify'])
      .then((cryptoKey) => {
        debug('Got crypto key ' + cryptoKey);
        return crypto.subtle.verify(alg.name, cryptoKey, guid_sig, guid);
      });
  },

  _getSha1: function _getSha1(devCert) {
    let browserWindow = Services.wm.getMostRecentWindow("navigator:browser");
    let crypto = browserWindow.crypto;
    if (!(devCert instanceof Uint8Array)) {
      return Promise.reject(
        new Error("Certificate must be an instance of Uint8Array"));
    }

    return crypto.subtle.digest("SHA-1", devCert)
    .then(function(arrayBuffer) {
      debug("Got Sha1: " + JSON.stringify(new Uint8Array(arrayBuffer)));
      return new Uint8Array(arrayBuffer);
    })
  },

  classID: Components.ID("{882a7463-2ca7-4d61-a89a-10eb6fd70478}"),
  contractID: "@mozilla.org/secureelement/access-control/ace;1",
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIAccessControlEnforcer])
};

this.NSGetFactory = XPCOMUtils.generateNSGetFactory([ACEService]);


'use strict';


/* globals log, is, ok, runTests, toggleNFC, runNextTest, 
   SpecialPowers, nfc, enableRE0, MozNDEFRecord */

const MARIONETTE_TIMEOUT = 30000;
const MARIONETTE_HEAD_JS = 'head.js';

const MANIFEST_URL = 'app://system.gaiamobile.org/manifest.webapp';
const NDEF_MESSAGE = [new MozNDEFRecord(new Uint8Array(0x01),
                                      new Uint8Array(0x84),
                                      new Uint8Array(0),
                                      new Uint8Array(0x20))];

let nfcPeers = [];
let sessionTokens = [];

/**git stati
 * Enables nfc and RE0 then registers onpeerready callback and once 
 * it's fired it creates mozNFCPeer and stores it for later. 
 * After disabling nfc tries to do mozNFCPeer.sendNdef which should 
 * fail with NfcNotEnabledError.
 */
function testNfcNotEnabledError() {
  log('nfc on, re0 on, set and fire onpeerready, nfc off, sendNdef -> ' +
      'should get NfcNotEnabledError');
  toggleNFC(true)
  .then(()=>enableRE0(0))
  .then(registerAndFireOnpeerready)
  .then(()=>toggleNFC(false))
  .then(()=>sendNDEFExpectError(nfcPeers[0], 'NfcNotEnabledError'))
  .then(afterEach); 
}

/**
 * Enables nfc and RE0, register onpeerready callback, once it fires
 * creates and stores mozNFCPeer. Disables nfc, enables nfc and 
 * once again registers and fires new onpeerready callback and stores
 * mozNfcPeer. Than fires sendNdef on the first stored peer which 
 * should have invalid session token and we should get NfcBadSessionIdError 
 */
function testNfcBadSessionIdError() {
  log('nfc on, re0 on, set/fire onpeerready, nfc off, nfc on, set/fire' +
      'onpeerrady, sendNdef on old mozNFCPeer -> NfcBadSessionIdError');
  toggleNFC(true)
  .then(()=>enableRE0(0))
  .then(registerAndFireOnpeerready)
  .then(()=>toggleNFC(false))
  .then(()=>toggleNFC(true))
  .then(()=>enableRE0(0))
  .then(registerAndFireOnpeerready)
  // we have 2 peers in nfcPeers array, peer0 has old/invalid session token
  .then(()=>sendNDEFExpectError(nfcPeers[0], 'NfcBadSessionIdError'))
  .then(()=>toggleNFC(false))
  .then(afterEach)
  .catch(function() {
    log('im in catch!!!!!!!');
    toggleNFC(false);
    afterEach();
  });
}

function afterEach() {
  nfcPeers = [];
  sessionTokens = [];
  //log('finishing test ******************************************************');
  runNextTest();
}

function registerAndFireOnpeerready() {
  //log('registerAndFireOnpeerready');
  ////log(nfcPeers);
  //log(sessionTokens);
  let deferred = Promise.defer();

  //log('setting on peerready handler');
  nfc.onpeerready = function(event) {
    //log('onpeerready fired, creating nfcPeer and storing session token: ' + event.detail);
    sessionTokens.push(event.detail);
    nfcPeers.push(nfc.getNFCPeer(event.detail));
    //log('removing on peerready handler');
    nfc.onpeerready = null;
    deferred.resolve();
  };

  //log('checkP2P request');
  let request = nfc.checkP2PRegistration(MANIFEST_URL);
  request.onsuccess = function() {
    //log('onsuccess should have result.status true: ' + request.result);
    is(request.result, true, 'P2P registration result');
    if(request.result) {
      //log('sending notify acceptedp2p')
      nfc.notifyUserAcceptedP2P(MANIFEST_URL);
    } else {
      //log('this should not happen');
      deferred.reject();
      //toggleNFC(false, runNextTest);
    }
  };

  request.onerror = function() {
    ok(false, 'not possible');
    nfc.onpeerready = null;
    deferred.rejected();
    toggleNFC(false, runNextTest);
  };

  //log('retufning promise in registerAndFireOnpeerready');
  return deferred.promise;
}

function sendNDEFExpectError(peer, errorMsg) {
  //log('sendingNdef and expext error: ' + errorMsg);
  let deferred = Promise.defer();

  //log('sending ndef');
  let req = peer.sendNDEF(NDEF_MESSAGE);
  //log('setting onsuccess handler');
  req.onsuccess = function() {
    //log('we should not be able to do this');
    ok(false, 'success on sending ndef not possible shoudl get: ' + errorMsg);
    deferred.resolve();
  };

  //log('setting onerror handler');
  req.onerror = function() {
    //log('got error as planned')
    ok(true, 'this should happen');
    is(req.error.name, errorMsg, 'Should have proper error name');
    deferred.resolve();
  };

  //log('returning promise in sendEndef, error:' + errorMsg);
  return deferred.promise;
}

let tests = [
  testNfcNotEnabledError,
  testNfcBadSessionIdError
];

/**
 * nfc-manager for mozNfc.checkP2PRegistration(manifestUrl)
 *  -> "NFC:CheckP2PRegistration" IPC
 * nfc-write to set/unset onpeerready 
 *  -> "NFC:RegisterPeerTarget", "NFC:UnregisterPeerTarget" IPC
 */
SpecialPowers.pushPermissions(
  [
    {'type': 'nfc-manager', 'allow': true, context: document}, 
    {'type': 'nfc-write', 'allow': true, context: document}
  ], runTests);

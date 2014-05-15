'use strict';

/* globals log, is, ok, runTests, runNextTest, SpecialPowers, nfc */

MARIONETTE_TIMEOUT = 30000;
MARIONETTE_HEAD_JS = 'head.js';

let MANIFEST_URL = 'app://system.gaiamobile.org/manifest.webapp';

/**
 * Failure scenarion without onpeerread handler registration
 * Nfc not enabled -> no session token 
 */
function testNoTargetNoSessionToken() {
  log('No opeerready handler, nfc not enabled');
  let request = nfc.checkP2PRegistration(MANIFEST_URL);
  
  request.onsuccess = function() {
    log('got on success, result should be false: ' + request.result);
    is(request.result, false, 
      'request.status should be false, onpeerready not registered, no session token');
    runNextTest();
  };

  request.onerror = function() {
    ok(false, 
      'not possible -> NfcContentHelper.handleCheckP2PRegistrationResponse');
    runNextTest();
  };
}

/**
 * Failure scenario onpeerready handler registered but Nfc not enabled
 * -> no session token
 */
function testWithTargetNoSessionToken() {
  log('onpeerready handler registered, nfc not enabled, no session token');

  nfc.onpeerready = function() {
    ok(false, 'onpeerready callback should not be fired');
    runNextTest();
  };

  let request = nfc.checkP2PRegistration(MANIFEST_URL);

  request.onsuccess = function() {
    log('got on success, result should be false: ' + request.result);
    is(request.result, false,
      'request.status should be false, onpeerready registered, no session token');
    runNextTest();
  };

  request.onerror = function() {
    ok(false, 
      'not possible -> NfcContentHelper.handleCheckP2PRegistrationResponse');
    runNextTest();
  };
}

/**
 * Success scenario, nfc enabled, activated RE0 (p2p ndef is received)
 */
function testWithSessionTokenWithTarget() {
  log('enabling nfc, activating RE0, registering onpeerready');
  enableNfc(true)
  .then( () => activateRE0() )
  .then( () => checkOnpeerreadyRegistered() )
  .then( () => enableNfc(false) )
  .then( () => runNextTest() );
}

function checkOnpeerreadyRegistered() {
  let deferred = Promise.defer();

  nfc.onpeerready = function() {
    ok(false, 'should not be fired, P2P was not accepted');
  };

  let request = nfc.checkP2PRegistration(MANIFEST_URL);
  request.onsuccess = function() {
    log('onsuccess should have result.status true ' + request.result);
    is(request.result, true,
      'request.status should be true, onpeerready registered, session token');
    log('removing onpeerready handler');
    nfc.onpeerready = null;
    deferred.resolve();
  };

  request.onerror = function() {
    log('onerror');
    ok(false, 
      'not possible -> NfcContentHelper.handleCheckP2PRegistrationResponse');
    nfc.onpeerready = null;
    deferred.resolve();
  };

  return deferred.promise;
}

function testWithSessionTokenNoTarget() {
  log('enabling nfc, activating re0, but not  registering onpeerready handler');
  enableNfc(true)
  .then( () => activateRE0() )
  .then( () => checkOnpeerreadyNotRegistered() )
  .then( () => enableNfc(false) )
  .then( () => runNextTest() );
}

function checkOnpeerreadyNotRegistered() {
  let deferred = Promise.defer();

  let request = nfc.checkP2PRegistration(MANIFEST_URL);
  request.onsuccess = function() {
    log('onsuccess should have result.status false ' + request.result);
    is(request.result, false,
      'request.status should be false, session token but onpeerready not registered');
    deferred.resolve();
  };

  request.onerror = function() {
    log('onerror');
    ok(false, 
      'not possible -> NfcContentHelper.handleCheckP2PRegistrationResponse');
    deferred.resolve();
  };

  return deferred.promise;
}


function enableNfc(enable) {
  let deferred = Promise.defer();
  log('changing nfc state to: ' + enable);
  let request = (enable) ? nfc.startPoll() : nfc.powerOff();
  request.onsuccess = function() {
    deferred.resolve();
  };
  request.onerror = function() {
    ok(false, 'operation failed, error ' + request.error.name);
    runNextTest();
  };

  return deferred.promise;
}

function activateRE0() {
  let deferred = Promise.defer();
  let cmd = 'nfc nci rf_intf_activated_ntf 0';

  emulator.run(cmd, function(result) {
    is(result.pop(), 'OK', 'check activation of RE0');
    deferred.resolve();
  });

  return deferred.promise;
}

let tests = [
  testNoTargetNoSessionToken,
  testWithTargetNoSessionToken,
  testWithSessionTokenWithTarget,
  testWithSessionTokenNoTarget
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




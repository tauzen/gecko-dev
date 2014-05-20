'use strict';

/* globals log, is, ok, runTests, toggleNFC, runNextTest, 
   SpecialPowers, nfc, activateRE0 */

const MARIONETTE_TIMEOUT = 30000;
const MARIONETTE_HEAD_JS = 'head.js';

const MANIFEST_URL = 'app://system.gaiamobile.org/manifest.webapp';
const FAKE_MANIFEST_URL = 'app://fake.gaiamobile.org/manifest.webapp';

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
    ok(false, 'onpeerready callback should not be fired, nfc not enabled');
    runNextTest();
  };

  let request = nfc.checkP2PRegistration(MANIFEST_URL);

  request.onsuccess = function() {
    log('got on success, result should be false: ' + request.result);
    is(request.result, false,
      'session token is available and it shouldnt be');
    nfc.onpeerready = null;
    runNextTest();
  };

  request.onerror = function() {
    ok(false, 
      'not possible -> NfcContentHelper.handleCheckP2PRegistrationResponse');
    nfc.onpeerready = null;
    runNextTest();
  };
}

/**
 * Success scenario, nfc enabled, activated RE0 (p2p ndef is received, 
 * creates session token) opeerreadyhandler registered, 
 */
function testWithSessionTokenWithTarget() {
  log('enabling nfc, activating RE0, registering onpeerready');
  runWithRE0(checkP2POnpeerreadyRegistered);
}

function checkP2POnpeerreadyRegistered() {
  let deferred = Promise.defer();

  nfc.onpeerready = function() {
    ok(false, 'should not be fired, P2P was not accepted');
  };

  let request = nfc.checkP2PRegistration(MANIFEST_URL);
  request.onsuccess = function() {
    log('onsuccess should have result.status true: ' + request.result);
    is(request.result, true,
      'should be true, onpeerready registered, session token available');
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

/**
 * Failure scenario, nfc enabled, activated RE0 (p2p ndef is received, 
 * creates session token) opeerready handler not registered, 
 */
function testWithSessionTokenNoTarget() {
  log('enabling nfc, activating re0, but not registering onpeerready handler');
  runWithRE0(checkP2POnpeerreadyNotRegistered);
}

function checkP2POnpeerreadyNotRegistered() {
  let deferred = Promise.defer();

  let request = nfc.checkP2PRegistration(MANIFEST_URL);
  request.onsuccess = function() {
    log('onsuccess should have result.status false: ' + request.result);
    is(request.result, false,
      'session token  avilable but onpeerready not registered');
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

/**
 * Failure scenario, nfc enabled, re0 activated, onpeerready registered,
 * checking wrong manifest url
 */
function testWithSessionTokenWrongTarget() {
  log('enabling nfc, activating re0, onpeerready registered, wrong manifest');
  runWithRE0(checkP2PWrongManifest);
}

function checkP2PWrongManifest() {
  let deferred = Promise.defer();

  nfc.onpeerready = function() {
    ok(false, 'should not be fired, P2P was not accepted');
  };

  let request = nfc.checkP2PRegistration(FAKE_MANIFEST_URL);
  request.onsuccess = function() {
    log('onsuccess should have result.status false: ' + request.result);
    is(request.result, false,
      'session token aviailable, but wrong manifest');
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

function runWithRE0(testScenario) {
  toggleNFC(true)
  .then(activateRE0)
  .then(testScenario)
  .then(() => toggleNFC(false))
  .then(runNextTest);
}

let tests = [
  testNoTargetNoSessionToken,
  testWithTargetNoSessionToken,
  testWithSessionTokenWithTarget,
  testWithSessionTokenNoTarget,
  testWithSessionTokenWrongTarget
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

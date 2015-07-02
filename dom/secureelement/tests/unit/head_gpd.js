/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

/* globals ok, equal, deepEqual, Components, SEUtils, XPCOMUtils */
/* exported HASH_APP1, HASH_APP2, HASH_APP3, HASH_APP4, AID_1, AID_2, AID_3,
            AID_4, AID_5, executRuleParsingTest, initRuleParsingTest */

const {classes: Cc, interfaces: Ci , utils: Cu} = Components;

Cu.import("resource://gre/modules/SEUtils.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

const HASH_APP1 = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                   0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
const HASH_APP2 = [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                   0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22];
const HASH_APP3 = [0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                   0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33];
const HASH_APP4 = [0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                   0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44];

const AID_1 = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x01];
const AID_2 = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x02];
const AID_3 = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x03];
const AID_4 = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x04];
const AID_5 = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x05];

let GPAccessRulesManager = null;

let MockUiccConnector = {
  set scenario(value) {
    this._scenario = value;
    this._step = 0;
  },

  get scenario() {
    return this._scenario;
  },

  _step: 0,

  _channelId: 1,

  openChannel: function(aid, cb) {
    equal(this._step, 0, "Channel should be opend before first step");
    ok(!!cb, "Callback object needs to be specified");
    equal(typeof cb.notifyOpenChannelSuccess, "function",
        "callback.notifyOpenChannelSuccess should be a funciton");
    cb.notifyOpenChannelSuccess(this._channelId);
  },

  exchangeAPDU: function(channel, cla, ins, p1, p2, data, le, cb) {
    equal(channel, this._channelId, "Exchange should happen on proper channel");
    ok(!!cb, "Callback object needs to be specified");
    equal(typeof cb.notifyExchangeAPDUResponse, "function",
       "callback.notifyExchangeAPDUResponse should be a function");

    let step = this._scenario.steps[this._step];
    ok(!!step, "Scenario steps already finished, invalid request");

    let request = this._convertAPDUToHexStr(cla, ins, p1, p2, data, le);
    let expectedRequest = step.request.replace(/\s+/g,"");
    equal(request, expectedRequest,
          "Request should match scenario step request");

    this._step += 1;
    cb.notifyExchangeAPDUResponse(0x90, 0x00, step.response.replace(/\s+/g,""));
  },

  closeChannel: function(channel, callback) {
    equal(this._step, this._scenario.steps.length,
          "Channel should be closed after last step");
    equal(channel, this._channelId, "Proper channel should be closed");
    if(callback) {
      callback.notifyCloseChannelSuccess();
    }
  },

  _convertAPDUToHexStr: function(cla, ins, p1, p2, data, le) {
    var dataLen  = (data) ? data.length/2 : 0;
    var bytes = [cla, ins, p1, p2, dataLen];
    return SEUtils.byteArrayToHexString(bytes) + ((dataLen) ? data : "");
  }
};

function handleRejectedPromise() {
  ok(false, "Promise should not be rejected");
}

function attachMockUiccConnector() {
  XPCOMUtils.defineLazyServiceGetter = (obj) => {
    obj.UiccConnector = MockUiccConnector;
  };
}

function initRuleParsingTest() {
  attachMockUiccConnector();

  GPAccessRulesManager =
    Cc["@mozilla.org/secureelement/access-control/rules-manager;1"]
    .createInstance(Ci.nsIAccessRulesManager);

  ok(!!GPAccessRulesManager, "RulesManager should be instantiated");
}

function executRuleParsingTest(scenario) {
  MockUiccConnector.scenario = scenario;
  
  return GPAccessRulesManager.getAccessRules().then((rules) => {
    rules.forEach((rule, idx) => {
      let expectedRule = MockUiccConnector.scenario.expectedRules[idx];

      deepEqual(rule.applet, expectedRule.applet, "scenario: " + scenario.name +
                ", rule " + idx + " applet should match.");
      deepEqual(rule.application, expectedRule.application, "scenario: " +
                scenario.name + ", rule " + idx + " application should match");
    });
  })
  .catch(handleRejectedPromise);
}

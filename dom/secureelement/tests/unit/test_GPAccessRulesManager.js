/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

/* globals run_next_test, add_test, ok, Components, SEUtils, XPCOMUtils */
/* exported run_test */

const {classes: Cc, interfaces: Ci, utils: Cu} = Components;

Cu.import("resource://gre/modules/Promise.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/SEUtils.jsm");

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


// Secure Element Access Control Version 1.0
// Annex C, C.1 First Example 
const GPD_SCENARIO1 = {
  name: "GPD example 1",
  expectedRules: [
    {
      applet: AID_1,
      application: Ci.nsIAccessRulesManager.DENY_ALL
    },
    {
      applet: AID_2,
      application: [HASH_APP1]
    },
    {
      applet: AID_3,
      application: [HASH_APP1]
    },
    {
      applet: Ci.nsIAccessRulesManager.ALL_APPLET,
      application: Ci.nsIAccessRulesManager.ALLOW_ALL
    }
  ],
  decisionAsserts: [
    {
      name: "Access denied for app 1 to applet 1.",
      applet: AID_1,
      application: HASH_APP1,
      expectedDecision: false
    },
    {
      name: "Access allowed for app 1 to applet 2.",
      applet: AID_2,
      application: HASH_APP1,
      expectedDecision: true
    },
    {
      name: "Access allowed for app 1 to applet 3.",
      applet: AID_3,
      application: HASH_APP1,
      expectedDecision: true
    },
    {
      name: "Access denied for app 2 to applet 1.",
      applet: AID_1,
      application: HASH_APP2,
      expectedDecision: false
    },
    {
      name: "Access denied for app 2 to applet 2.",
      applet: AID_2,
      application: HASH_APP2,
      expectedDecision: false
    },
    {
      name: "Access denied for app 2 to applet 3.",
      applet: AID_3,
      application: HASH_APP2,
      expectedDecision: false
    },
    {
      name: "Access allowed for app 1 to other applet.",
      applet: [0xA0, 0x00, 0x00, 0x01, 0x51, 0xFF],
      application: HASH_APP1,
      expectedDecision: true
    },
    {
      name: "Access allowed for app 2 to other applet.",
      applet: [0xA0, 0x00, 0x00, 0x01, 0x51, 0xFF],
      application: HASH_APP2,
      expectedDecision: true
    }
  ],
  steps: [
    {
      "desc": "Select ODF",
      "request": "00 A4 00 04 02 50 31",
      "response": "62 22" +
                     "82 02 41 21" +
                     "83 02 50 31" +
                     "A5 03" +
                        "C0 01 40" +
                     "8A 01 05" +
                     "8B 06 6F 06 01 01 00 01" +
                     "80 02 00 10" +
                     "81 02 00 22" +
                     "88 00"
    },
    {
      "desc": "Read ODF",
      "request": "00 B0 00 00 00", //10",
      "response": "A7 06" +
                     "30 04" +
                         "04 02 52 07"
    },
    {
      "desc": "Select DODF",
      "request": "00 A4 00 04 02 52 07",
      "response": "62 22" +
                     "82 02 41 21" +
                     "83 02 44 01" +
                     "A5 03" +
                        "C0 01 40" +
                     "8A 01 05" +
                     "8B 06 6F 06 01 01 00 01" +
                     "80 02 00 A4" +
                     "81 02 00 2B" +
                     "88 00"
    },
    {
      "desc": "Read DODF",
      "request": "00 B0 00 00 00", //A4",
      "response": "A1 29" +
                     "30 00" +
                     "30 0F" +
                        "0C 0D 47 50 20 53 45 20 41 63 63 20 43 74 6C" +
                     //      ; G  P     S  E     A  c  c     C  t  l
                     "A1 14" +
                        "30 12" +
                           "06 0A 2A 86 48 86 FC 6B 81 48 01 01" +
                           "30 04" +
                              "04 02 42 00"            // ACMain file ID (4200)
    },
    {
      "desc": "Select ACMF",
      "request": "00 A4 00 04 02 42 00",
      "response": "62 22" +
                     "82 02 41 21" +
                     "83 02 43 00" +
                     "A5 03" +
                        "C0 01 40" +
                     "8A 01 05" +
                     "8B 06 6F 06 01 01 00 00" +
                     "80 02 00 14" +
                     "81 02 00 26" +
                     "88 00"
    },
    {
      "desc": "Read ACMF",
      "request": "00 B0 00 00 00", //14",
      "response": "30 10" +
                     "04 08 01 02 03 04 05 06 07 08" +    // Refresh tag
                     "30 04" +
                        "04 02 43 00"
    },
    {
      "desc": "Select ACRules",
      "request": "00 A4 00 04 02 43 00",
      "response": "62 22" +
                     "82 02 41 21" +
                     "83 02 43 00" +
                     "A5 03" +
                        "C0 01 40" +
                     "8A 01 05" +
                     "8B 06 6F 06 01 01 00 00" +
                     "80 02 00 14" +
                     "81 02 00 40" +
                     "88 00"
    },
    {
      "desc": "Read ACRules",
      "request": "00 B0 00 00 00", //14",
      "response": "30 10   A0 08 04 06 A0 00 00 01 51 01   30 04 04 02 43 10" +
                  "30 10   A0 08 04 06 A0 00 00 01 51 02   30 04 04 02 43 11" +
                  "30 10   A0 08 04 06 A0 00 00 01 51 03   30 04 04 02 43 11" +
                  "30 08   82 00                           30 04 04 02 43 12"
    },
    {
      "desc": "Select ACCondition 1",
      "request": "00 A4 00 04 02 43 10",
      "response": "62 22" +
                     "82 02 41 21" +
                     "83 02 43 00" +
                     "A5 03" +
                        "C0 01 40" +
                     "8A 01 05" +
                     "8B 06 6F 06 01 01 00 00" +
                     "80 02 00 00" +
                     "81 02 00 00" +
                     "88 00"
    },
    {
      "desc": "Select ACCondition 2",
      "request": "00 A4 00 04 02 43 11",
      "response": "62 22" +
                     "82 02 41 21" +
                     "83 02 43 00" +
                     "A5 03" +
                        "C0 01 40" +
                     "8A 01 05" +
                     "8B 06 6F 06 01 01 00 00" +
                     "80 02 00 18" +
                     "81 02 00 18" +
                     "88 00"
    },
    {
      "desc": "Read ACCondition 2",
      "request": "00 B0 00 00 00", //18",
      "response": "30 16" +
                     "04 14 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11"
    },
    {
      "desc": "Select ACCondition 3",
      "request": "00 A4 00 04 02 43 12",
      "response": "62 22" +
                     "82 02 41 21" +
                     "83 02 43 00" +
                     "A5 03" +
                        "C0 01 40" +
                     "8A 01 05" +
                     "8B 06 6F 06 01 01 00 00" +
                     "80 02 00 02" +
                     "81 02 00 02" +
                     "88 00"
    },
    {
      "desc": "Read ACCondition 3",
      "request": "00 B0 00 00 00", //02",
      "response": "30 00"
    }
  ]
};

let MockUiccConnector = {
  set scenario(value) {
    this._scenario(value);
    this._step = 0;
  },
  _step: 0,

  _channelId: 1,

  openChannel: function(aid, cb) {
    ok(this._step === 0, "Channel should be opend before first step");
    ok(!!cb, "Callback object needs to be specified");
    ok((typeof cb.notifyOpenChannelSuccess) === "function",
        "callback.notifyOpenChannelSuccess should be a funciton");
    cb.notifyOpenChannelSuccess(this._channelId);
  },

  exchangeAPDU: function(channel, cla, ins, p1, p2, data, le, cb) {
    ok(channel === this._channelId, "Exchange should happen on proper channel");
    ok(!!cb, "Callback object needs to be specified");
    ok((typeof cb.notifyExchangeAPDUResponse) === "function",
       "callback.notifyExchangeAPDUResponse should be a function");

    let step = this._scenario.steps[this._step];
    ok(!!step, "Scenario steps already finished, invalid request");

    let request = this._convertAPDUToHexStr(cla, ins, p1, p2, data, le);
    let expectedRequest = step.request.replace(/\s+/g,"");
    ok(request === expectedRequest,
       "Request should match scenario step request");

    this._step += 1;
    cb.notifyExchangeAPDUResponse(0x90, 0x00, step.response.replace(/\s+/g,""));
  },

  closeChannel: function(channel, callback) {
    ok(this._step === this._scenario.steps.length,
       "Channel should be closed after last step");
    ok(channel, this._channelId, "Proper channel should be closed");
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

let GPAccessRulesManager = null;

function run_test() {
  XPCOMUtils.defineLazyServiceGetter = (obj) => {
    obj.UiccConnector = MockUiccConnector;
  };

  GPAccessRulesManager =
    Cc["@mozilla.org/secureelement/access-control/rules-manager;1"]
    .createInstance(Ci.nsIAccessRulesManager);

  ok(!!GPAccessRulesManager, "RulesManager should be instantiated");
  run_next_test();
}

add_test(function test_GPDScenario1_rule_parsing() {
  MockUiccConnector.scenario = GPD_SCENARIO1;
});

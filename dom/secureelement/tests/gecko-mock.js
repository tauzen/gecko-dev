"use strict";

/* globals console, debug */
/* exported Components */

window.Components = {
  classes: {},
  interfaces: {
      nsIAccessRulesManager: {
        ALLOW_ALL: 1,
        DENY_ALL: 2,
        ALL_APPLET: 3
      }
  },
  utils: {
    import: function() {
      debug("Components.utils.import" + arguments);
    }
  },
  results: {},
  ID: () => {}
};

var MockParentProcessMessageManager = {
  addMessageListener: function() {
    debug("MockParentProcessMessageManager.addMessageListener" + arguments);
  }
};

var MockRilContentHelper = {
  openChannel: function(aid, callbackObj) {
    debug("Opening channel: " + aid);
    let channelId = 1;
    this.mockPosition = 0;
    callbackObj.notifyOpenChannelSuccess(channelId);
  },
  exchangeAPDU: function(channel, cla, ins, p1, p2, data, le, callbackObj) {
    var byteArrayToString = function(bytes) {
      var str = "";

      bytes.forEach(function(oneByte) {
        var hex = oneByte.toString(16);
        if (hex.length === 1) {
          hex = "0" + hex;
        }

        str += hex;
      });

      return str;
    };

    var prettify = function(str) {
      return str.replace(/\s+/g, "")
                .replace(/(..)/g, "$1 ")
                .replace(/\s$/, "")
                .toUpperCase();
    };

    var sanitize = function(str) {
      return str.replace(/\s+/g, "")
                .toUpperCase();
    };

    let scenario = window.ACE_TEST_SCENARIO;

    if (!scenario) {
      debug("No scenario '" + scenario + "' found.");
      return;
    }

    let mock = scenario.steps;

    debug("Mock command #" + this.mockPosition);
    var dataLen  = (data) ? data.length/2 : 0;
    var bytes = [cla, ins, p1, p2, dataLen];
    
    debug('APDU ' + bytes + ', data: ' + data)
    let command = mock[this.mockPosition];
    let request = prettify(byteArrayToString(bytes) + ((dataLen) ? data : ''));

    if (command.request !== request) {
      debug("Mock " + command.desc + ": invalid request: " + request +
            " at position " + this.mockPosition);
      return callbackObj.notifyExchangeAPDUResponse(0x6A, 0x82, null);
    }

    this.mockPosition += 1;
    callbackObj.notifyExchangeAPDUResponse(0x90, 0x00, sanitize(command.response));
  },

  closeChannel: function(channel, callback) {
    if(callback) {
      callback.notifyCloseChannelSuccess();
    }
  },
};

var MockWebapps = {
  getAppByManifestURL: function() {
    debug("MockWebapps.getAppByManifestURL" + arguments);
  }
};

var addMockProperty = function(target, name, contractId, interfaceName) {
  var mockServices = {
    "@mozilla.org/parentprocessmessagemanager;1 -- nsIMessageListenerManager": MockParentProcessMessageManager,
    "@mozilla.org/secureelement/connector/uicc;1 -- nsISecureElementConnector": MockRilContentHelper,
  };

  var mockModules = {
    "resource://gre/modules/Webapps.jsm": MockWebapps,
  };

  var impl = null;
  if (arguments.length === 3) {
    impl = mockModules[contractId];
  } else {
    var id = contractId + " -- " + interfaceName;
    impl = mockServices[id];
  }

  if (!impl) {
    debug("No mock implementation found for " + contractId + "@" + interfaceName);
    return;
  }

  debug("Mock implementation for " + contractId + "@"  + interfaceName + " attached as " + name);
  target[name] = impl;
};

window.XPCOMUtils = {
  defineLazyServiceGetter: addMockProperty,
  defineLazyModuleGetter: addMockProperty,
  defineLazyGetter: addMockProperty,
  generateQI: () => {},
  generateNSGetFactory: () => {}
};

window.ppmm = {
  addMessageListener: function() {
    debug("ppmm.addMessageListener " + arguments);
  }
};

window.dump = function(str) {
  console.log(str);
};

window.SE = { DEBUG_ACE: true };

window.Task = {
  async: function(makeGenerator){
    return function () {
      var generator = makeGenerator.apply(this, arguments);

      function handle(result){
        // result => { done: [Boolean], value: [Object] }
        if (result.done) return Promise.resolve(result.value);

        return Promise.resolve(result.value).then(function (res){
          return handle(generator.next(res));
        }, function (err){
          return handle(generator.throw(err));
        });
      }

      try {
        return handle(generator.next());
      } catch (ex) {
        return Promise.reject(ex);
      }
    }
  }
};

window.GP = {};
window.GP.ODF_DF = [0x50, 0x31];

/* ISO 7816-4: secure messaging */
window.GP.CLA_SM = 0x00;

/* ISO 7816-4, 5.4.1 table 11 */
window.GP.INS_SF = 0xA4; // select file
window.GP.INS_GR = 0xC0; // get response
window.GP.INS_RB = 0xB0; // read binary

/* ISO 7816-4: select file, see 6.11.3, table 58 & 59 */
window.GP.P1_SF_DF = 0x00; // select DF
window.GP.P2_SF_FCP = 0x04; // return FCP

/* ISO 7816-4: read binary, 6.1.3. P1 and P2 describe offset of the first byte
   to be read. We always read the whole files at the moment. */
window.GP.P1_RB = 0x00;
window.GP.P2_RB = 0x00;

/* ISO 7816-4: get response, 7.1.3 table 74,  P1-P2 '0000' (other values RFU) */
window.GP.P1_GR = 0x00;
window.GP.P2_GR = 0x00;

/* ISO 7816-4: 5.1.5 File Control Information, Table 1. For FCP and FMD. */
window.GP.TAG_PROPRIETARY = 0x00;
window.GP.TAG_NON_TLV = 0x53;
window.GP.TAG_BER_TLV = 0x73;

/* ASN.1 tags */
window.GP.TAG_SEQUENCE = 0x30;
window.GP.TAG_OCTETSTRING = 0x04;
window.GP.TAG_OID = 0x06; // Object Identifier

/* ISO 7816-4: 5.1.5 File Control Information, Templates. */
window.GP.TAG_FCP = 0x62; // File control parameters template
window.GP.TAG_FMD = 0x64; // File management data template
window.GP.TAG_FCI = 0x6F; // File control information template

/* EF_DIR tags */
window.GP.TAG_APPLTEMPLATE = 0x61;
window.GP.TAG_APPLIDENTIFIER = 0x4F;
window.GP.TAG_APPLLABEL = 0x50;
window.GP.TAG_APPLPATH = 0x51;

window.GP.TAG_GPD_ALL = 0x82; // EF-ACRules - GPD spec. "all applets"

/* ASN.1 tags */
window.GP.TAG_SEQUENCE = 0x30;
window.GP.TAG_OCTETSTRING = 0x04;
window.GP.TAG_OID = 0x06; // Object Identifier

/* ISO 7816-4: 5.1.5 File Control Information, Templates. */
window.GP.TAG_FCP = 0x62; // File control parameters template
window.GP.TAG_FMD = 0x64; // File management data template
window.GP.TAG_FCI = 0x6F; // File control information template

/* EF_DIR tags */
window.GP.TAG_APPLTEMPLATE = 0x61;
window.GP.TAG_APPLIDENTIFIER = 0x4F;
window.GP.TAG_APPLLABEL = 0x50;
window.GP.TAG_APPLPATH = 0x51;

window.GP.TAG_GPD_ALL = 0x82; // EF-ACRules - GPD spec. "all applets"

/* Generic TLVs that are parsed */
window.GP.TAG_GPD_AID = 0xA0; // AID in the EF-ACRules - GPD spec, "one applet"
window.GP.TAG_EXTERNALDO = 0xA1; // External data objects - PKCS#15
window.GP.TAG_INDIRECT = 0xA5; // Indirect value.
window.GP.TAG_EF_ODF = 0xA7; // Elemenetary File Object Directory File

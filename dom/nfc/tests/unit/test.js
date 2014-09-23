'use strict';

/* globals run_next_test, add_test, do_print, ok, Components */
/* exported run_test */

const {classes: Cc, interfaces: Ci, utils: Cu, results: Cr} = Components;

Cu.import('resource://gre/modules/Promise.jsm');
//Cu.import('resource://gre/modules/HCIEventTransactionSystemMessageConfigurator.js');
const HCIEventTransactionSystemMessageConfigurator =
        Cc['@mozilla.org/dom/system-messages/configurator/nfc-hci-event-transaction;1']
        .createInstance(Ci.nsISystemMessagesConfigurator);

const MANIFEST_URL = 'app://system.gaiamobile.org/manifest.webapp';
const PAGE_URL = 'app://system.gaiamobile.org/index.html';
const TYPE = 'nfc-hci-event-transaction';
const EXTRA = null;

function run_test() {
  ok(!!HCIEventTransactionSystemMessageConfigurator,
     'Configurator should be instantiated');
  ok((typeof HCIEventTransactionSystemMessageConfigurator.shouldDispatch) === 'function',
     'shouldDispatch should be function');

  run_next_test();
}

add_test(function test_shouldDispatch() {
  var dispatch = HCIEventTransactionSystemMessageConfigurator
  .shouldDispatch(MANIFEST_URL, PAGE_URL, TYPE, null, EXTRA);
  do_print(typeof dispatch);

  dispatch.then((result) => {
    ok(!result, 'Should be false without message');
    run_next_test();
  });
});
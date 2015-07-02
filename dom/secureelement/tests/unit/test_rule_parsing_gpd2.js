/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

/* globals Ci, AID_1, AID_2, AID_3, AID_4, AID_5, HASH_APP1, HASH_APP2,
           HASH_APP3, HASH_APP4, initRuleParsingTest, executRuleParsingTest,
           run_next_test */
/* exported run_test */

// Secure Element Access Control Version 1.0
// Annex C, C.2 Second Example 
let GPD_SCENARIO2 = {
  name: "GPD example 2",
  expectedRules: [
    {
      applet: AID_1,
      application: Ci.nsIAccessRulesManager.ALLOW_ALL,
    },
    {
      applet: AID_2,
      application: [HASH_APP1]
    },
    {
      applet: AID_3,
      application: [HASH_APP1, HASH_APP2, HASH_APP3]
    },
    {
      applet: AID_4,
      application: Ci.nsIAccessRulesManager.DENY_ALL,
    },
    {
      applet: AID_5,
      application: Ci.nsIAccessRulesManager.DENY_ALL,
    },
    {
      applet: Ci.nsIAccessRulesManager.ALL_APPLET,
      application: Ci.nsIAccessRulesManager.DENY_ALL,
    }
  ],
  // not used in rule parsing scenario
  decisionAsserts: [
    {
      name: "Access allowed for app 1 to applet 1.",
      applet: AID_1,
      application: HASH_APP1,
      expectedDecision: true
    },
    {
      name: "Access allowed for app 2 to applet 1.",
      applet: AID_1,
      application: HASH_APP2,
      expectedDecision: true
    },
    {
      name: "Access allowed for app 3 to applet 1.",
      applet: AID_1,
      application: HASH_APP3,
      expectedDecision: true
    },
    {
      name: "Access allowed for app 4 to applet 1.",
      applet: AID_1,
      application: HASH_APP4,
      expectedDecision: true
    },
    {
      name: "Access allowed for app 1 to applet 2.",
      applet: AID_2,
      application: HASH_APP1,
      expectedDecision: true
    },
    {
      name: "Access denied for app 2 to applet 2.",
      applet: AID_2,
      application: HASH_APP2,
      expectedDecision: false
    },
    {
      name: "Access denied for app 3 to applet 2.",
      applet: AID_2,
      application: HASH_APP3,
      expectedDecision: false
    },
    {
      name: "Access denied for app 4 to applet 2.",
      applet:AID_2,
      application: HASH_APP4,
      expectedDecision: false
    },
    {
      name: "Access allowed for app 1 to applet 3.",
      applet: AID_3,
      application: HASH_APP1,
      expectedDecision: true
    },
    {
      name: "Access allowed for app 2 to applet 3.",
      applet: AID_3,
      application: HASH_APP2,
      expectedDecision: true
    },
    {
      name: "Access allowed for app 3 to applet 3.",
      applet: AID_3,
      application: HASH_APP3,
      expectedDecision: true
    },
    {
      name: "Access denied for app 4 to applet 3.",
      applet: AID_3,
      application: HASH_APP4,
      expectedDecision: false
    },
    {
      name: "Access denied for app 1 to applet 4.",
      applet: AID_4,
      application: HASH_APP1,
      expectedDecision: false
    },
    {
      name: "Access denied for app 2 to applet 4.",
      applet: AID_4,
      application: HASH_APP2,
      expectedDecision: false
    },
    {
      name: "Access denied for app 3 to applet 4.",
      applet: AID_4,
      application: HASH_APP3,
      expectedDecision: false
    },
    {
      name: "Access denied for app 4 to applet 4.",
      applet: AID_4,
      application: HASH_APP4,
      expectedDecision: false
    },
    {
      name: "Access denied for app 1 to applet 5.",
      applet: AID_5,
      application: HASH_APP1,
      expectedDecision: false
    },
    {
      name: "Access denied for app 2 to applet 5.",
      applet: AID_5,
      application: HASH_APP2,
      expectedDecision: false
    },
    {
      name: "Access denied for app 3 to applet 5.",
      applet: AID_5,
      application: HASH_APP3,
      expectedDecision: false
    },
    {
      name: "Access denied for app 4 to applet 5.",
      applet: AID_5,
      application: HASH_APP4,
      expectedDecision: false
    },
    {
      name: "Access denied for app 1 to other applets.",
      applet: [0xA0, 0x00, 0x00, 0x01, 0x51, 0xFF],
      application: HASH_APP1,
      expectedDecision: false
    },
    {
      name: "Access denied for app 2 to other applets.",
      applet: [0xA0, 0x00, 0x00, 0x01, 0x51, 0xFF],
      application: HASH_APP2,
      expectedDecision: false
    },
    {
      name: "Access denied for app 3 to other applets.",
      applet: [0xA0, 0x00, 0x00, 0x01, 0x51, 0xFF],
      application: HASH_APP3,
      expectedDecision: false
    },
    {
      name: "Access denied for app 4 to other applets.",
      applet: [0xA0, 0x00, 0x00, 0x01, 0x51, 0xFF],
      application: HASH_APP4,
      expectedDecision: false
    },
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
                  "30 10   A0 08 04 06 A0 00 00 01 51 03   30 04 04 02 43 12" +
                  "30 10   A0 08 04 06 A0 00 00 01 51 04   30 04 04 02 43 13" +
                  "30 10   A0 08 04 06 A0 00 00 01 51 05   30 04 04 02 43 13" +
                  "30 08   82 00                           30 04 04 02 43 13"
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
                     "80 02 00 02" +
                     "81 02 00 00" +
                     "88 00"
    },
    {
      "desc": "Read ACCondition 1",
      "request": "00 B0 00 00 00", //02",
      "response": "30 00"
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
                     "80 02 00 48" +
                     "81 02 00 48" +
                     "88 00"
    },
    {
      "desc": "Read ACCondition 3",
      "request": "00 B0 00 00 00", //48",
      "response": "30 16" +
                     "04 14 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11" +
                  "30 16" +
                     "04 14 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22" +
                  "30 16" +
                     "04 14 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33"
    },
    {
      "desc": "Select ACCondition 4",
      "request": "00 A4 00 04 02 43 13",
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
    }
  ]
};

function run_test() {
  initRuleParsingTest();
  executRuleParsingTest(GPD_SCENARIO2)
  .then(run_next_test);
}

/* vim: set ft=javascript ts=2 et sw=2 tw=80: */
/* Any copyright is dedicated to the Public Domain.
 http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

// Test the fontfamily tooltip on shorthand properties

const PAGE_CONTENT = [
  '<style type="text/css">',
  '  #testElement {',
  '    font: italic bold .8em/1.2 Arial;',
  '  }',
  '</style>',
  '<div id="testElement">test element</div>'
].join("\n");

let test = asyncTest(function*() {
  yield addTab("data:text/html;charset=utf-8,font family shorthand tooltip test");

  info("Creating the test document");
  content.document.body.innerHTML = PAGE_CONTENT;

  info("Opening the rule view");
  let {toolbox, inspector, view} = yield openRuleView();

  info("Selecting the test node");
  yield selectNode("#testElement", inspector);

  yield testRuleView(view);

  info("Opening the computed view");
  let {toolbox, inspector, view} = yield openComputedView();

  yield testComputedView(view);
});

function* testRuleView(ruleView) {
  info("Testing font-family tooltips in the rule view");

  let panel = ruleView.previewTooltip.panel;

  // Check that the rule view has a tooltip and that a XUL panel has been created
  ok(ruleView.previewTooltip, "Tooltip instance exists");
  ok(panel, "XUL panel exists");

  // Get the computed font family property inside the font rule view
  let propertyList = ruleView.element.querySelectorAll(".ruleview-propertylist");
  let fontExpander = propertyList[1].querySelectorAll(".ruleview-expander")[0];
  fontExpander.click();

  let rule = getRuleViewRule(ruleView, "#testElement");
  let valueSpan = rule.querySelector(".ruleview-computed .ruleview-propertyvalue");

  // And verify that the tooltip gets shown on this property
  yield assertHoverTooltipOn(ruleView.previewTooltip, valueSpan);

  let description = panel.getElementsByTagName("description")[0];
  is(description.style.fontFamily, "Arial", "Tooltips contains correct font-family style");
}

function* testComputedView(computedView) {
  info("Testing font-family tooltips in the computed view");

  let panel = computedView.tooltip.panel;
  let {valueSpan} = getComputedViewProperty(computedView, "font-family");

  yield assertHoverTooltipOn(computedView.tooltip, valueSpan);

  let description = panel.getElementsByTagName("description")[0];
  is(description.style.fontFamily, "Arial", "Tooltips contains correct font-family style");
}

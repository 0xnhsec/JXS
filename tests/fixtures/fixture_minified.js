/**
 * tests/fixtures/fixture_minified.js
 * Fixture: Simulated minified JS bundle (no beautify applied).
 * Tests that regex patterns work correctly on minified content.
 *
 * Used by: tests/test_extraction.py
 */
!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}n.m=e,n.c=t,n.d=function(e,t,r){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var r=Object.create(null);if(n.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:e}),2&t&&"object"==typeof e)for(var o in e)n.d(r,o,function(t){return e[t]}.bind(null,o));return r},n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return n.d(t,"a",t),t},n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p="";var fetchData=function(e){return fetch("/api/v1/data/"+e).then(function(e){return e.json()})};var submitForm=function(e){return axios.post("/api/form/submit",e)};document.getElementById("output").innerHTML=userInput;eval(untrustedCode);//# sourceMappingURL=https://cdn.example.com/static/js/chunk.js.map

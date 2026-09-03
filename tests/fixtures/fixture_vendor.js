/**
 * tests/fixtures/fixture_vendor.js
 * Fixture: Simulated vendor bundle (jQuery-like) to test vendor classification.
 * Expected: classified as 'vendor', findings severity downgraded.
 *
 * Used by: tests/test_extraction.py — vendor_classifier validation
 */

/*! jQuery JavaScript Library v3.7.0
 * https://jquery.com/
 *
 * Copyright OpenJS Foundation and other contributors
 * Released under the MIT license
 * https://jquery.org/license
 */
( function( global, factory ) {
	"use strict";
	if ( typeof module === "object" && typeof module.exports === "object" ) {
		module.exports = global.document ? factory( global, true ) : function( w ) {
			if ( !w.document ) { throw new Error( "jQuery requires a window with a document" ); }
			return factory( w );
		};
	} else { factory( global ); }
} )( typeof window !== "undefined" ? window : this, function( window, noGlobal ) {
"use strict";
var arr = [];
var getProto = Object.getPrototypeOf;
var slice = arr.slice;
var flat = arr.flat ? function( array ) { return arr.flat.call( array ); } : function( array ) { return arr.concat.apply( [], array ); };
var push = arr.push;
var indexOf = arr.indexOf;
var class2type = {};
var toString = class2type.toString;
var hasOwn = class2type.hasOwnProperty;
var fnToString = hasOwn.toString;
var ObjectFunctionString = fnToString.call( Object );
var support = {};
var isFunction = function isFunction( obj ) { return typeof obj === "function" && typeof obj.nodeType !== "number" && typeof obj.item !== "function"; };

// Note: this has intentional innerHTML usage that should be downgraded because vendor
jQuery.fn.html = function( value ) {
	return access( this, function( value ) {
		if ( value === undefined ) {
			return self.innerHTML;  // read only — not a sink
		}
		jQuery.cleanData( getAll( elem, false ) );
		elem.innerHTML = value;  // SINK in vendor — should be downgraded to medium/low
	}, null, value, arguments.length );
};

} );

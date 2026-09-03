/**
 * tests/fixtures/fixture_dom_sinks.js
 * Fixture: JS file with intentional DOM sink patterns for DOM_SINK_PATTERN validation.
 * Expected findings: innerHTML, eval, dangerouslySetInnerHTML, document.write, location.href
 *
 * Used by: tests/test_extraction.py — DOM_SINK_PATTERN validation (PRD 8k)
 */

// Case 1: innerHTML assignment — HIGH (should match)
function renderUserComment(comment) {
    const el = document.getElementById('comment-box');
    el.innerHTML = comment;  // SINK: direct innerHTML assignment
}

// Case 2: eval — HIGH (should match)
function executeConfig(configStr) {
    const result = eval(configStr);  // SINK: eval with string
    return result;
}

// Case 3: dangerouslySetInnerHTML — HIGH (should match)
function UserBio({ bio }) {
    return React.createElement('div', {
        dangerouslySetInnerHTML = { __html: bio }  // SINK: React raw HTML
    });
}

// Case 4: document.write — HIGH (should match)
function injectScript(src) {
    document.write('<script src="' + src + '"></script>');  // SINK: document.write
}

// Case 5: location.href assignment — HIGH (redirect)
function redirect(url) {
    location.href = url;  // SINK: open redirect vector
}

// Case 6: insertAdjacentHTML — HIGH (should match)
function appendNotification(msg) {
    document.getElementById('notify').insertAdjacentHTML('beforeend', msg);  // SINK
}

// Case 7: window.open — HIGH (should match)
function openExternal(url) {
    window.open(url, '_blank');  // SINK
}

// Case 8: NOT a sink — textContent (should NOT match)
function safeRender(text) {
    document.getElementById('safe').textContent = text;  // NOT a sink
}

// Case 9: NOT a sink — innerText (should NOT match)
function safeUpdate(text) {
    el.innerText = text;  // NOT a sink
}

// Case 10: outerHTML — HIGH (should match)
function replaceElement(newHtml) {
    document.getElementById('target').outerHTML = newHtml;  // SINK
}

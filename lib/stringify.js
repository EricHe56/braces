'use strict';

const utils = require('./utils');

module.exports = (ast, options = {}) => {
  const maxDepth = utils.walkLimit();

  const stringify = (node, depth = 0) => {
    // This walker uses one stack frame per nesting level. Guard the recursion so
    // that a deeply nested AST passed in directly cannot exhaust the call stack
    // and terminate the process (CVE-2026-93687).
    if (depth > maxDepth) {
      throw new RangeError(`Brace pattern exceeds max depth (${maxDepth})`);
    }

    const invalidBlock = options.escapeInvalid && utils.isInvalidBrace(node);
    const invalidNode = node.invalid === true && options.escapeInvalid === true;
    let output = '';

    if (node.value) {
      if ((invalidBlock || invalidNode) && utils.isOpenOrClose(node)) {
        return '\\' + node.value;
      }
      return node.value;
    }

    if (node.nodes) {
      for (const child of node.nodes) {
        output += stringify(child, depth + 1);
      }
    }
    return output;
  };

  return stringify(ast);
};


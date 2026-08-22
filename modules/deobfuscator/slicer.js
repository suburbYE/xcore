/**
 * xcore Phase 2 — Data-Flow Backward Slicer v3
 * 
 *  Input:  _unflattened.js
 *  Output: _sliced.js
 * 
 * Changes v3:
 *   - Fix: FunctionDeclaration defs now include the whole function body
 *   - Fix: Variable declarations now include their init expressions 
 *   - Scope chain check: def must be in same scope or ancestor of use
 *   - Verbose mode with -v flag
 */

const fs = require('fs');
const acorn = require('acorn');

const args = process.argv.slice(2);
if (args.length < 2) {
    console.error('Usage: node slicer.js <input.js> <output.js> [--sink varName] [--entry funcName] [--max-depth N] [-v]');
    process.exit(1);
}
const inputFile = args[0];
const outputFile = args[1];
const sinkIdx = args.indexOf('--sink');
const entryIdx = args.indexOf('--entry');
const depthIdx = args.indexOf('--max-depth');
const verbose = args.includes('-v');
const userSink = sinkIdx >= 0 ? args[sinkIdx + 1] : null;
const entryFunc = entryIdx >= 0 ? args[entryIdx + 1] : null;
const MAX_DEPTH = depthIdx >= 0 ? parseInt(args[depthIdx + 1]) : 5;

const __t0 = Date.now();

let code;
try { code = fs.readFileSync(inputFile, 'utf-8'); }
catch (e) { console.error('Cannot read input:', e.message); process.exit(1); }

let ast;
try { ast = acorn.parse(code, { ecmaVersion: 2022, sourceType: 'script', locations: true, ranges: true }); }
catch (e) { console.error('Parse error:', e.message); process.exit(1); }
console.error(`[slicer] Parse done (${Date.now() - __t0}ms)`);

// ─── Scope Manager ────────────────────────────────────────────
let scopeId = 0;
const ROOT_SCOPE = 0;
const nodeScopeMap = new Map();
const scopeChildren = new Map();
const scopeParent = new Map();
let currentScope = ROOT_SCOPE;

scopeChildren.set(ROOT_SCOPE, new Set());
scopeParent.set(ROOT_SCOPE, -1);

function pushScope() {
    const parent = currentScope;
    scopeId++;
    currentScope = scopeId;
    scopeChildren.set(currentScope, new Set());
    scopeParent.set(currentScope, parent);
    scopeChildren.get(parent).add(currentScope);
    return currentScope;
}

function popScope() { currentScope = scopeParent.get(currentScope) || ROOT_SCOPE; }

function assignScope(node, sid) { nodeScopeMap.set(node, sid); }

function scopeChainContains(ancestor, descendant) {
    let cur = descendant;
    while (cur !== -1 && cur != null) {
        if (cur === ancestor) return true;
        cur = scopeParent.get(cur);
    }
    return false;
}

// ─── Data structures ──────────────────────────────────────────
const defMap = new Map();    // varName → [{node, scope}]
const useMap = new Map();    // varName → [{node, scope}]
const nodeToStmt = new Map();
const allStmts = [];
const stmtScope = new Map();
let currentStmt = null;

const STMT_TYPES = new Set([
    'ExpressionStatement', 'VariableDeclaration', 'FunctionDeclaration',
    'IfStatement', 'ForStatement', 'ForInStatement', 'ForOfStatement',
    'WhileStatement', 'DoWhileStatement', 'SwitchStatement', 'ReturnStatement',
    'TryStatement', 'ThrowStatement', 'LabeledStatement',
    'BreakStatement', 'ContinueStatement',
]);

// ─── Walk (build def-use) ─────────────────────────────────────
function walk(node, parent) {
    if (!node || typeof node !== 'object' || !node.type) return;
    node._parent = parent;
    const sid = currentScope;
    assignScope(node, sid);

    const prevStmt = currentStmt;

    // Track ALL statements including those nested inside functions
    if (STMT_TYPES.has(node.type) && node.type !== 'BlockStatement') {
        currentStmt = node;
        allStmts.push(node);
        stmtScope.set(node, sid);
    }
    // For nodes inside a function body, parent statement is the function declaration
    nodeToStmt.set(node, currentStmt || prevStmt);

    const createsScope = node.type === 'FunctionDeclaration' || 
                         node.type === 'FunctionExpression' ||
                         node.type === 'ArrowFunctionExpression';

    // For FunctionDeclaration: the function name is a def in the enclosing scope
    if (createsScope && node.type === 'FunctionDeclaration' && node.id) {
        addDef(node.id.name, node, sid);
    }

    if (createsScope) pushScope();

    // DEF: VariableDeclarator
    if (node.type === 'VariableDeclarator' && node.id)
        collectDef(node.id, currentScope);

    // DEF: AssignmentExpression
    if (node.type === 'AssignmentExpression' && node.left)
        collectDef(node.left, currentScope);

    // DEF: UpdateExpression
    if (node.type === 'UpdateExpression' && node.argument && node.argument.type === 'Identifier')
        addDef(node.argument.name, node, currentScope);

    // DEF: ForIn/ForOf left
    if ((node.type === 'ForInStatement' || node.type === 'ForOfStatement') && node.left) {
        if (node.left.type === 'VariableDeclaration')
            for (const d of node.left.declarations) collectDef(d.id, currentScope);
        else collectDef(node.left, currentScope);
    }

    // DEF: CatchClause
    if (node.type === 'CatchClause' && node.param)
        collectDef(node.param, currentScope);

    // DEF: Function params
    if (createsScope)
        for (const p of node.params) collectDef(p, currentScope);

    // USE: Identifier
    if (node.type === 'Identifier' && isUseSite(node, parent))
        addUse(node.name, node, currentScope);

    // Recurse
    for (const key of Object.keys(node)) {
        if (['_parent', 'start', 'end', 'range', 'loc'].includes(key)) continue;
        const val = node[key];
        if (Array.isArray(val)) {
            for (const c of val) {
                if (c && typeof c.type === 'string') walk(c, node);
            }
        } else if (val && typeof val.type === 'string') {
            walk(val, node);
        }
    }

    if (createsScope) popScope();
    if (STMT_TYPES.has(node.type) && node.type !== 'BlockStatement') currentStmt = prevStmt;
}

function collectDef(pattern, scope) {
    if (!pattern) return;
    if (pattern.type === 'Identifier') { addDef(pattern.name, pattern, scope); return; }
    if (pattern.type === 'ObjectPattern') { for (const p of pattern.properties) collectDef(p.value || p.argument, scope); return; }
    if (pattern.type === 'ArrayPattern') { for (const e of pattern.elements) if (e) collectDef(e, scope); return; }
    if (pattern.type === 'AssignmentPattern') { collectDef(pattern.left, scope); return; }
    if (pattern.type === 'RestElement') { collectDef(pattern.argument, scope); return; }
    if (pattern.type === 'MemberExpression') {
        let obj = pattern; while (obj.type === 'MemberExpression') obj = obj.object;
        if (obj.type === 'Identifier') addDef(obj.name, obj, scope);
    }
}

function addDef(name, node, scope) {
    if (!defMap.has(name)) defMap.set(name, []);
    defMap.get(name).push({ node, scope });
    assignScope(node, scope);
}

function addUse(name, node, scope) {
    if (!useMap.has(name)) useMap.set(name, []);
    useMap.get(name).push({ node, scope });
    assignScope(node, scope);
}

function isUseSite(idNode, parent) {
    if (!parent) return true;
    if (parent.type === 'MemberExpression' && parent.property === idNode && !parent.computed) return false;
    if (parent.type === 'FunctionDeclaration' && parent.id === idNode) return false;
    if (parent.type === 'VariableDeclarator' && parent.id === idNode) return false;
    if (parent.type === 'LabeledStatement' && parent.label === idNode) return false;
    if (parent.type === 'BreakStatement' && parent.label === idNode) return false;
    if (parent.type === 'ContinueStatement' && parent.label === idNode) return false;
    if (parent.type === 'CatchClause' && parent.param === idNode) return false;
    // FunctionExpression / ArrowFunctionExpression params are defs, not uses
    if ((parent.type === 'FunctionExpression' || parent.type === 'ArrowFunctionExpression') &&
        parent.params && parent.params.includes(idNode)) return false;
    return true;
}

walk(ast, null);
console.error(`[slicer] Walk done (${Date.now() - __t0}ms)`);

console.error(`[slicer] Scopes: ${scopeId}, Statements: ${allStmts.length}, Def vars: ${defMap.size}`);

// ─── Build prototype method map (for cross-function call tracing) ──
const protoMethodMap = new Map(); // methodName → { funcNode, scope }
(function scanProtoMethods(node) {
    if (!node || typeof node !== 'object' || !node.type) return;
    if (node.type === 'AssignmentExpression' &&
        node.left && node.left.type === 'MemberExpression' &&
        node.left.property && node.left.property.type === 'Identifier' &&
        node.right && (node.right.type === 'FunctionExpression' || node.right.type === 'ArrowFunctionExpression')) {
        const propName = node.left.property.name;
        const funcScope = nodeScopeMap.get(node.right);
        if (!protoMethodMap.has(propName)) {
            protoMethodMap.set(propName, { funcNode: node.right, scope: funcScope });
        }
    }
    for (const key of Object.keys(node)) {
        if (['start', 'end', 'range', 'loc', '_parent'].includes(key)) continue;
        const val = node[key];
        if (Array.isArray(val)) {
            for (const c of val) if (c && typeof c.type === 'string') scanProtoMethods(c);
        } else if (val && typeof val.type === 'string') {
            scanProtoMethods(val);
        }
    }
})(ast);
if (verbose) {
    const methods = [...protoMethodMap.keys()];
    console.error(`[slicer] Proto methods: ${methods.length} (${methods.join(', ')})`);
}

// ─── Taint Sinks ──────────────────────────────────────────────
const taintSinks = new Set();     // "scopeId::varName"
const taintedStmts = new Set();
const worklist = [];

function sinkKey(scope, varName) { return `${scope}::${varName}`; }

function markSink(scope, varName, depth) {
    if (!varName) return;
    if (depth > MAX_DEPTH) return;
    const key = sinkKey(scope, varName);
    if (taintSinks.has(key)) return;

    taintSinks.add(key);
    if (verbose) console.error(`  [sink d=${depth}] ${scope}::${varName}`);

    const defs = defMap.get(varName);
    if (!defs) return;

    for (const d of defs) {
        const inChain = scopeChainContains(d.scope, scope);
        if (!inChain) continue;

        const stmt = nodeToStmt.get(d.node);
        // Only taint if statement is at same scope as def — prevents
        // FunctionExpression params from pulling in outer ReturnStatement
        if (stmt && (stmtScope.get(stmt) || ROOT_SCOPE) === d.scope) {
            taintedStmts.add(stmt);
        }

        const enclosing = getEnclosingExpr(d.node, d.scope);
        if (enclosing) {
            const usedVars = new Set();
            collectUsedVars(enclosing, usedVars);
            for (const uv of usedVars) {
                worklist.push({ scope: d.scope, varName: uv, depth: depth + 1 });
            }
        }
    }
}

function getEnclosingExpr(defNode, scope) {
    // defNode is the AST node where the variable is defined (Identifier / FunctionDeclaration)
    // For Identifiers, the parent node is where the def happens (VariableDeclarator, Assignment, etc.)
    if (defNode.type === 'VariableDeclarator') return defNode.init;
    if (defNode.type === 'AssignmentExpression') return defNode.right;
    if (defNode.type === 'UpdateExpression') return defNode;
    // FunctionDeclaration — taint the declaration itself, do NOT inline the body.
    // The emitter handles full function body inclusion via brace matching.
    if (defNode.type === 'FunctionDeclaration' || defNode.type === 'FunctionExpression' ||
        defNode.type === 'ArrowFunctionExpression') {
        return null;
    }
    // defNode is an Identifier — check its _parent
    if (defNode.type === 'Identifier' && defNode._parent) {
        const parent = defNode._parent;
        if (parent.type === 'VariableDeclarator' && parent.init) return parent.init;
        if (parent.type === 'AssignmentExpression') return parent.right;
    }
    // CatchClause / function param — these are inputs, no backward propagation
    return null;
}

function collectUsedVars(node, out) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'Identifier') { out.add(node.name); return; }
    if (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') return;
    if (node.type === 'FunctionDeclaration') {
        // Function bodies: recurse into body to find all uses
        if (node.body) collectUsedVars(node.body, out);
        return;
    }
    if (node.type === 'BlockStatement') {
        for (const stmt of node.body) collectUsedVars(stmt, out);
        return;
    }
    for (const key of Object.keys(node)) {
        if (['start', 'end', 'range', 'loc', '_parent'].includes(key)) continue;
        const val = node[key];
        if (Array.isArray(val)) {
            for (const c of val) {
                if (c && typeof c.type === 'string') collectUsedVars(c, out);
            }
        } else if (val && typeof val.type === 'string') {
            collectUsedVars(val, out);
        }
    }
}

// ─── Find entry function scope (supports FunctionDeclaration + prototype method) ────
function findFunctionScope(funcName) {
    // 1. FunctionDeclaration
    for (const stmt of allStmts) {
        if (stmt.type === 'FunctionDeclaration' && stmt.id && stmt.id.name === funcName) {
            const declScope = nodeScopeMap.get(stmt) || ROOT_SCOPE;
            const childScopes = scopeChildren.get(declScope);
            if (childScopes && childScopes.size > 0)
                return Math.max(...childScopes);
        }
    }
    // 2. Prototype/object method assignment: X.prototype.Y = function(){…} or X.Y = function(){…}
    // Handle both direct AssignmentExpression and SequenceExpression (comma chain)
    function checkAssignment(ae, stmt) {
        if (!ae.right || (ae.right.type !== 'FunctionExpression' && ae.right.type !== 'ArrowFunctionExpression')) return false;
        if (!(ae.left.type === 'MemberExpression' && !ae.left.computed &&
              ae.left.property && ae.left.property.type === 'Identifier' &&
              ae.left.property.name === funcName)) return false;
        const parentScope = stmtScope.get(stmt) || ROOT_SCOPE;
        const childScopes = scopeChildren.get(parentScope);
        const fnStart = ae.right.start, fnEnd = ae.right.end;
        if (childScopes && childScopes.size > 0) {
            for (const cs of childScopes) {
                for (const s of allStmts) {
                    if (stmtScope.get(s) === cs && s.start >= fnStart && s.end <= fnEnd) {
                        if (verbose) console.error(`[slicer] Found entry "${funcName}" via proto method, scope=${cs}`);
                        return cs;
                    }
                }
            }
        }
        return null;
    }
    // Helper: try to find funcName in an expression node (Assignment or Sequence)
    function findInExpression(expr, stmt) {
        if (expr.type === 'AssignmentExpression') {
            const result = checkAssignment(expr, stmt);
            if (result) return result;
        } else if (expr.type === 'SequenceExpression') {
            for (const ae of expr.expressions) {
                if (ae.type === 'AssignmentExpression') {
                    const result = checkAssignment(ae, stmt);
                    if (result) return result;
                }
            }
        }
        return null;
    }
    
    for (const stmt of allStmts) {
        let expr = null;
        if (stmt.type === 'ExpressionStatement') expr = stmt.expression;
        else if (stmt.type === 'ReturnStatement' && stmt.argument) expr = stmt.argument;
        if (!expr) continue;
        const result = findInExpression(expr, stmt);
        if (result) return result;
    }
    return null;
}

// ─── Detect sinks ─────────────────────────────────────────────
function findReturnSinks() {
    // Determine target scope: --entry funcName → find that function's scope
    let targetScope = entryFunc ? findFunctionScope(entryFunc) : null;

    let returnCount = 0;
    for (const stmt of allStmts) {
        if (stmt.type !== 'ReturnStatement' || !stmt.argument) continue;
        const sid = stmtScope.get(stmt) || ROOT_SCOPE;
        if (targetScope !== null && sid !== targetScope) continue;
        returnCount++;
        const vars = new Set();
        collectTopLevelRefs(stmt.argument, vars);
        for (const v of vars) markSink(sid, v, 0);
    }
    // Fallback: if entry func not found, use all returns
    if (entryFunc && returnCount === 0) {
        console.error(`[slicer] WARNING: entry function "${entryFunc}" not found, falling back to all returns`);
        for (const stmt of allStmts) {
            if (stmt.type !== 'ReturnStatement' || !stmt.argument) continue;
            const sid = stmtScope.get(stmt) || ROOT_SCOPE;
            const vars = new Set();
            collectTopLevelRefs(stmt.argument, vars);
            for (const v of vars) markSink(sid, v, 0);
        }
    }
    return returnCount;
}

function collectTopLevelRefs(node, out) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'Identifier') { out.add(node.name); return; }
    if (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') return;
    for (const key of Object.keys(node)) {
        if (['start', 'end', 'range', 'loc', '_parent'].includes(key)) continue;
        const val = node[key];
        if (Array.isArray(val)) {
            for (const c of val) {
                if (c && typeof c.type === 'string') collectTopLevelRefs(c, out);
            }
        } else if (val && typeof val.type === 'string') {
            collectTopLevelRefs(val, out);
        }
    }
}

// Init sinks
if (userSink) markSink(ROOT_SCOPE, userSink, 0);
const matchedReturns = findReturnSinks();

console.error(`[slicer] Initial sinks: ${taintSinks.size} (returns matched: ${matchedReturns})`);

// ─── Backward Propagation ─────────────────────────────────────
let iterations = 0;
while (worklist.length > 0 && iterations < 500) {
    const item = worklist.shift();
    iterations++;
    markSink(item.scope, item.varName, item.depth);
}

console.error(`[slicer] Propagation: ${iterations} iters, ${taintSinks.size} total sinks (${Date.now() - __t0}ms)`);

// ─── Also include USE-site statements ─────────────────────────
console.error(`[slicer] USE-site pass start (${Date.now() - __t0}ms)`);
// Optimized: iterate taintSinks → uses → mark statements (not allStmts × taintSinks)
for (const key of taintSinks) {
    const idx = key.indexOf('::');
    const keyScope = parseInt(key.slice(0, idx));
    const varName = key.slice(idx + 2);
    const uses = useMap.get(varName);
    if (!uses) continue;
    for (const u of uses) {
        const stmt = nodeToStmt.get(u.node);
        if (!stmt || taintedStmts.has(stmt)) continue;
        if (scopeChainContains(keyScope, u.scope || (stmtScope.get(stmt) || ROOT_SCOPE))) {
            if (code.slice(stmt.start, stmt.start + 20).includes('defineProperty')) {
                console.error(`[slicer] DBG defineProperty via USE-site: keyScope=${keyScope} var=${varName} u.scope=${u.scope} stmtScope=${stmtScope.get(stmt)}`);
            }
            taintedStmts.add(stmt);
        }
    }
}
console.error(`[slicer] USE-site pass done (${Date.now() - __t0}ms)`);

// ─── Cross-function Call Tracing ──────────────────────────────
if (MAX_DEPTH > 0 && protoMethodMap.size > 0) {
    console.error(`[slicer] Call trace pass start (${Date.now() - __t0}ms)`);

    function findCallsInStmt(stmt) {
        const found = [];
        (function walkExpr(node) {
            if (!node || typeof node !== 'object' || !node.type) return;
            if (node.type === 'CallExpression' && node.callee && node.callee.type === 'MemberExpression') {
                const prop = node.callee.property;
                if (prop && prop.type === 'Identifier') {
                    const methodInfo = protoMethodMap.get(prop.name);
                    if (methodInfo) found.push(methodInfo);
                }
            }
            for (const key of Object.keys(node)) {
                if (['start', 'end', 'range', 'loc', '_parent'].includes(key)) continue;
                const val = node[key];
                if (Array.isArray(val)) {
                    for (const c of val) if (c && typeof c.type === 'string') walkExpr(c);
                } else if (val && typeof val.type === 'string') {
                    walkExpr(val);
                }
            }
        })(stmt);
        return found;
    }

    for (let callDepth = 0; callDepth < MAX_DEPTH; callDepth++) {
        const newStmts = new Set();
        const newParamSinks = []; // [{scope, varName}]

        for (const stmt of taintedStmts) {
            const calls = findCallsInStmt(stmt);
            for (const { funcNode, scope: funcScope } of calls) {
                if (!funcNode.body || funcNode.body.type !== 'BlockStatement') continue;
                for (const bodyStmt of funcNode.body.body) {
                    if (STMT_TYPES.has(bodyStmt.type) && bodyStmt.type !== 'BlockStatement') {
                        newStmts.add(bodyStmt);
                    }
                }
                for (const p of funcNode.params) {
                    if (p.type === 'Identifier') {
                        // Use the body scope (where the param is actually defined), not funcScope
                        // funcScope is the FunctionExpression node's own scope (parent), too permissive for USE-site
                        const defs = defMap.get(p.name);
                        let bodyScope = funcScope;
                        if (defs) {
                            for (const d of defs) {
                                if (d.node === p) { bodyScope = d.scope; break; }
                            }
                        }
                        newParamSinks.push({ scope: bodyScope, varName: p.name });
                    }
                }
            }
        }
        if (newStmts.size === 0) break;

        for (const s of newStmts) taintedStmts.add(s);

        // Add param sinks and run USE-site for them
        for (const { scope: sScope, varName } of newParamSinks) {
            const key = sinkKey(sScope, varName);
            if (taintSinks.has(key)) continue;
            taintSinks.add(key);
            taintedStmtsUsed = false;
            const uses = useMap.get(varName);
            if (uses) {
                for (const u of uses) {
                    const stmt = nodeToStmt.get(u.node);
                    if (!stmt || taintedStmts.has(stmt)) continue;
                    if (scopeChainContains(sScope, u.scope || (stmtScope.get(stmt) || ROOT_SCOPE))) {
                        taintedStmts.add(stmt);
                    }
                }
            }
        }

        if (verbose) console.error(`  [call d=${callDepth}] +${newStmts.size} stmts, ${newParamSinks.length} params`);
    }

    console.error(`[slicer] Call trace pass done (${Date.now() - __t0}ms)`);
}

// ─── Output ───────────────────────────────────────────────────
// Build a set of tainted FunctionDeclaration nodes for dedup
const taintedFuncIds = new Set();
for (const stmt of allStmts) {
    if (stmt.type === 'FunctionDeclaration' && taintedStmts.has(stmt))
        taintedFuncIds.add(stmt.start); // use start offset as unique id
}

// Check if a statement is inside a tainted FunctionDeclaration
function isInsideTaintedFunction(stmt) {
    for (const funcStmt of allStmts) {
        if (funcStmt.type !== 'FunctionDeclaration' || !taintedStmts.has(funcStmt)) continue;
        if (funcStmt.start <= stmt.start && stmt.end <= funcStmt.end)
            return true;
    }
    return false;
}

// CFG Dead Return Pruning: after first unconditional ReturnStatement
// in a given scope, delete subsequent tainted statements at that scope.
{
    const scopeReturned = new Set();
    const byStart = [...taintedStmts].sort((a, b) => (a.start || 0) - (b.start || 0));
    for (const stmt of byStart) {
        const sScope = stmtScope.get(stmt) || ROOT_SCOPE;
        if (scopeReturned.has(sScope)) {
            taintedStmts.delete(stmt);
            continue;
        }
        if (stmt.type === 'ReturnStatement') scopeReturned.add(sScope);
    }
}

const ordered = [...taintedStmts].sort((a, b) => (a.start || 0) - (b.start || 0));

const MAX_STMT_SIZE = 5000; // Skip emitting huge statements (IIFE wrappers etc)
const outLines = [];
for (const stmt of ordered) {
    if (stmt.start == null || stmt.end == null) continue;

    // Skip statements inside already-tainted FunctionDeclarations
    if (stmt.type !== 'FunctionDeclaration' && isInsideTaintedFunction(stmt)) continue;

    // For huge VariableDeclarations, extract var names and emit stubs
    const stmtSize = stmt.end - stmt.start;
    if (stmtSize > MAX_STMT_SIZE && stmt.type === 'VariableDeclaration') {
        const names = [];
        for (const decl of stmt.declarations) {
            if (decl.id && decl.id.name) names.push(decl.id.name);
        }
        if (names.length > 0) {
            outLines.push(`// [external] var ${names.join(', ')} = ...; // ${stmtSize} bytes omitted`);
        }
        continue;
    }

    // Extract statement text directly (don't back up to line start — minified code has very long lines)
    let sliceStart = stmt.start;
    let sliceEnd = stmt.end;
    while (sliceEnd < code.length && code[sliceEnd] === ' ') sliceEnd++;
    if (sliceEnd < code.length && code[sliceEnd] === ';') sliceEnd++;

    // For multi-line statements (function bodies, etc.), include full range
    if (stmt.type === 'FunctionDeclaration') {
        // Include the entire function including body
        sliceEnd = stmt.end;
        // Find matching closing brace
        let braceCount = 0;
        let found = false;
        for (let i = stmt.start; i < code.length; i++) {
            if (code[i] === '{') { braceCount++; found = true; }
            if (code[i] === '}') { braceCount--; if (found && braceCount === 0) { sliceEnd = i + 1; break; } }
        }
    }

    const slice = code.slice(sliceStart, sliceEnd).trim();
    if (slice) outLines.push(slice);
}

// Deduplicate identical lines (common with multiple sink hits on same statement)
const seen = new Set();
const deduped = [];
for (const line of outLines) {
    if (!seen.has(line)) {
        seen.add(line);
        deduped.push(line);
    }
}

const origSize = code.length;
const sliced = deduped.join('\n');
const slicedSize = sliced.length;
const reduction = ((1 - slicedSize / origSize) * 100).toFixed(1);

fs.writeFileSync(outputFile, sliced, 'utf-8');

console.error(`[slicer] Tainted stmts: ${taintedStmts.size} / ${allStmts.length}`);
console.error(`[slicer] Size: ${origSize.toLocaleString()} → ${slicedSize.toLocaleString()} bytes (-${reduction}%)`);
console.error(`[slicer] Total time: ${Date.now() - __t0}ms`);

// Report
fs.writeFileSync(outputFile.replace(/\.js$/, '_slice_report.json'), JSON.stringify({
    original_size: origSize, sliced_size: slicedSize, reduction_pct: parseFloat(reduction),
    taint_sinks_count: taintSinks.size, iterations, tainted_statements: taintedStmts.size,
    total_statements: allStmts.length,
}, null, 2));

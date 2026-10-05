'use strict';
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const logger = require('../../src/logger');

describe('src/logger', () => {
  let out; let err; let origLog; let origErr;
  beforeEach(() => {
    out = []; err = [];
    origLog = console.log; origErr = console.error;
    console.log = (...a) => out.push(a.join(' '));
    console.error = (...a) => err.push(a.join(' '));
  });
  afterEach(() => { console.log = origLog; console.error = origErr; delete process.env.LOG_LEVEL; });

  it('defaults to info: info is written, debug is not', () => {
    delete process.env.LOG_LEVEL;
    logger.info('hello'); logger.debug('hidden');
    assert.equal(out.length, 1);
    assert.match(out[0], /\[INFO\] hello/);
  });

  it('routes warn/error to stderr and info/debug to stdout', () => {
    process.env.LOG_LEVEL = 'debug';
    logger.debug('d'); logger.info('i'); logger.warn('w'); logger.error('e');
    assert.equal(out.length, 2);
    assert.equal(err.length, 2);
  });

  it('honours level filtering and "silent"', () => {
    process.env.LOG_LEVEL = 'error';
    logger.warn('w'); logger.error('e');
    assert.equal(err.length, 1);
    process.env.LOG_LEVEL = 'silent';
    logger.error('nope');
    assert.equal(err.length, 1);
  });

  it('falls back to info for an unknown level', () => {
    process.env.LOG_LEVEL = 'bogus';
    logger.info('x'); logger.debug('y');
    assert.equal(out.length, 1);
  });

  it('formats metadata as key=value, quoting values with whitespace and skipping empties', () => {
    logger.info('evt', { a: 1, b: 'two words', c: '', d: undefined, e: null, f: { x: 1 } });
    assert.match(out[0], /a=1/);
    assert.match(out[0], /b="two words"/);
    assert.match(out[0], /f=\{"x":1\}/);
    assert.ok(!/ c=/.test(out[0]) && !/ d=/.test(out[0]) && !/ e=/.test(out[0]));
  });

  it('prints stacks on separate lines and never inline', () => {
    logger.error('boom', { error: 'bad', stack: 'Error: bad\n  at foo' });
    assert.ok(!err[0].split('\n')[0].includes('at foo'));
    assert.ok(err.join('\n').includes('    Error: bad'));
  });

  it('errInfo extracts message/code/stack and tolerates null', () => {
    const e = Object.assign(new Error('nope'), { code: 'E_X' });
    const info = logger.errInfo(e);
    assert.equal(info.error, 'nope');
    assert.equal(info.code, 'E_X');
    assert.ok(info.stack.includes('nope'));
    assert.deepEqual(logger.errInfo(null), {});
  });
});

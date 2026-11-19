import assert from 'node:assert/strict';
import test from 'node:test';
import { reissue } from './flow.mjs';

const modes = {
    CSP: { reader: 'A CSP', media: 'csp-a' },
    PKCS11: { reader: 'A PKCS#11', media: 'pkcs-a' },
};
const other = { reader: 'B CSP', media: 'csp-b' };

function scenario({
    initial,
    desired,
    finalMode = modes[desired],
    readers = Object.values(modes).concat(other),
    removeError,
}) {
    const calls = [];
    const adapter = {
        async generate(name, subject, target) {
            calls.push(['generate', name, subject, target]);
            return target
                ? { ...finalMode, id: 'new-id', csr: 'new-csr' }
                : { ...initial, id: 'initial-id', csr: 'initial-csr' };
        },
        async readers() { return readers; },
        async remove(container) {
            calls.push(['remove', container.id]);
            if (removeError) throw removeError;
        },
    };
    const run = () => reissue({
        adapter, modes, mockFormat: desired, serialNumber: '000123',
        name: 'reissue-test', subject: 'CN=Test',
        report(message, value) { calls.push([message, value]); },
    });
    return { run, calls };
}

for (const format of Object.keys(modes)) {
    test('keeps the first CSR for ' + format, async () => {
        const { run, calls } = scenario({ initial: modes[format], desired: format });
        assert.deepEqual(await run(), { csr: 'initial-csr', regenerated: false });
        assert.deepEqual(calls.map(([name]) => name), [
            'generate', 'Мок POST /api/v1/company/test/common/key-format', 'Ответ мок API',
        ]);
        assert.deepEqual(calls[1][1], { serialNumber: '000123' });
    });

    test('regenerates with ' + format + ' on the configured reader', async () => {
        const initial = format === 'CSP' ? modes.PKCS11 : modes.CSP;
        const { run, calls } = scenario({ initial, desired: format });
        assert.deepEqual(await run(), { csr: 'new-csr', regenerated: true });
        assert.deepEqual(calls.slice(-2), [
            ['remove', 'initial-id'],
            ['generate', 'reissue-test', 'CN=Test', { keyFormat: format, reader: modes[format].reader }],
        ]);
    });
}

test('mock HTTP failure aborts before removal or regeneration', async () => {
    const { run, calls } = scenario({ initial: modes.PKCS11, desired: 'error' });
    await assert.rejects(run, /HTTP 503/);
    assert.equal(calls.length, 2);
});

test('removal failure aborts before regeneration', async () => {
    const { run, calls } = scenario({
        initial: modes.PKCS11, desired: 'CSP', removeError: new Error('Delete failed'),
    });
    await assert.rejects(run, /Delete failed/);
    assert.deepEqual(calls.at(-1), ['remove', 'initial-id']);
});

test('missing or duplicate target aborts before removal', async () => {
    for (const readers of [[modes.PKCS11, other], [modes.PKCS11, modes.CSP, modes.CSP]]) {
        const { run, calls } = scenario({ initial: modes.PKCS11, desired: 'CSP', readers });
        await assert.rejects(run, /Считыватель отсутствует/);
        assert.ok(!calls.some(([name]) => name === 'remove'));
    }
});

test('another initially selected token cannot reach the API', async () => {
    const { run, calls } = scenario({ initial: other, desired: 'CSP' });
    await assert.rejects(run, /Первый контейнер/);
    assert.equal(calls.length, 1);
});

test('other token or changed Media cannot produce a final result', async () => {
    for (const finalMode of [other, { ...modes.CSP, media: 'changed' }]) {
        const { run } = scenario({ initial: modes.PKCS11, desired: 'CSP', finalMode });
        await assert.rejects(run, /Итоговый контейнер/);
    }
});

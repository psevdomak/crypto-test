import assert from 'node:assert/strict';
import test from 'node:test';
import { reissue } from './flow.mjs';

const serialNumber = '979006804';
const cspMedia = 'rutoken_ecp_3a5a7554';
const pkcsMedia = 'pkcs11_rutoken_ecp_3a5a7554';
const otherMedia = 'rutoken_ecp_3a5a7555';
const modes = {
    CSP: { reader: 'A CSP', media: cspMedia },
    PKCS11: { reader: 'A PKCS#11', media: pkcsMedia },
};
const other = { reader: 'B CSP', media: otherMedia };

function container(mode, csr = 'initial-csr') {
    return { ...mode, id: ['SCARD', mode.media, 'native-id'].join('\\'), csr };
}

function scenario({ initial, desired, finalMode = modes[desired], readers, generateError, removeError }) {
    const calls = [];
    const adapter = {
        async generate(name, subject, target) {
            calls.push(['generate', name, subject, target]);
            if (target && generateError) throw generateError;
            return target ? container(finalMode, 'new-csr') : { csr: 'initial-csr', ...initial };
        },
        async readers() {
            return readers || Object.values(modes).concat(other);
        },
        async remove(created) {
            calls.push(['remove', created.id]);
            if (removeError) throw removeError;
        },
    };
    const run = () => reissue({
        adapter, mockFormat: desired, name: 'reissue-test',
        report(message, value) { calls.push([message, value]); },
    });
    return { run, calls };
}

for (const format of Object.keys(modes)) {
    test('detects the serial and keeps the first CSR for ' + format, async () => {
        const initial = container(modes[format]);
        const { run, calls } = scenario({ initial, desired: format });
        assert.deepEqual(await run(), { csr: 'initial-csr', regenerated: false, serialNumber });
        assert.deepEqual(calls.find(([name]) => name.startsWith('Мок POST'))?.[1], { serialNumber });
        assert.ok(!calls.some(([name]) => name === 'remove'));
    });

    test('regenerates with ' + format + ' on the same token with a second token connected', async () => {
        const initial = container(format === 'CSP' ? modes.PKCS11 : modes.CSP);
        const { run, calls } = scenario({ initial, desired: format });
        assert.deepEqual(await run(), { csr: 'new-csr', regenerated: true, serialNumber });
        const changes = calls.filter(([name]) => ['generate', 'Проверка итогового контейнера', 'remove'].includes(name));
        assert.deepEqual(changes.map(([name]) => name), [
            'generate', 'generate', 'Проверка итогового контейнера', 'remove',
        ]);
        assert.deepEqual(changes[0], ['generate', 'reissue-test', 'CN=CryptoPro reissue test', undefined]);
        assert.deepEqual(changes[1], [
            'generate', 'reissue-test-final', 'CN=CryptoPro reissue test',
            { keyFormat: format, reader: modes[format].reader },
        ]);
        assert.deepEqual(changes[3], ['remove', initial.id]);
    });
}

test('recognizes FQCN with a reader prefix and different case', async () => {
    const { run } = scenario({
        initial: { id: 'unrecognized', fqcn: '\\\\.\\A CSP\\SCARD\\RUTOKEN_ECP_3A5A7554\\0000\\0000' },
        desired: 'CSP',
    });
    assert.equal((await run()).serialNumber, serialNumber);
});

test('recognizes a Lite serial in the documented format', async () => {
    const { run } = scenario({
        initial: { id: 'SCARD\\rutoken_lt_2e823e54\\1000\\B9A6' }, desired: 'CSP',
    });
    assert.equal((await run()).serialNumber, '780287572');
});

test('mock HTTP failure aborts before removal or regeneration', async () => {
    const { run, calls } = scenario({ initial: container(modes.PKCS11), desired: 'error' });
    await assert.rejects(run, /HTTP 503/);
    assert.equal(calls.filter(([name]) => name === 'generate' || name === 'remove').length, 1);
});

test('removal failure reports the final container was already created', async () => {
    const initial = container(modes.PKCS11);
    const { run, calls } = scenario({ initial, desired: 'CSP', removeError: new Error('Delete failed') });
    await assert.rejects(run, /Итоговый контейнер создан.*Delete failed/);
    assert.equal(calls.at(-2)[0], 'Проверка итогового контейнера');
    assert.deepEqual(calls.at(-1), ['remove', initial.id]);
});

test('missing or ambiguous target aborts before removal', async () => {
    for (const readers of [
        [modes.PKCS11, other],
        [modes.PKCS11, modes.CSP, { ...modes.CSP, reader: 'A other CSP reader' }],
        [modes.PKCS11, modes.CSP, { ...other, reader: modes.CSP.reader }],
    ]) {
        const { run, calls } = scenario({ initial: container(modes.PKCS11), desired: 'CSP', readers });
        await assert.rejects(run, /отсутствует или найден неоднозначно/);
        assert.ok(!calls.some(([name]) => name === 'remove'));
    }
});

test('unknown or out-of-range serial never reaches the mock', async () => {
    for (const id of ['SCARD\\some_other_device_3a5a7554\\key', 'SCARD\\rutoken_ecp_00000001\\key']) {
        const { run, calls } = scenario({ initial: { id }, desired: 'CSP' });
        await assert.rejects(run, /Не удалось однозначно определить серийный номер/);
        assert.ok(!calls.some(([name]) => name.startsWith('Мок POST')));
    }
});

test('container metadata must agree on the physical token', async () => {
    const { run, calls } = scenario({
        initial: { ...container(modes.CSP), media: otherMedia }, desired: 'CSP',
    });
    await assert.rejects(run, /Media контейнера указывает на другой токен/);
    assert.equal(calls.length, 1);
});

test('failed generation leaves the initial container intact', async () => {
    const { run, calls } = scenario({
        initial: container(modes.PKCS11), desired: 'CSP', generateError: new Error('CreateRequest failed'),
    });
    await assert.rejects(run, /CreateRequest failed/);
    assert.ok(!calls.some(([name]) => name === 'remove'));
});

test('wrong token or format aborts without removing the initial container', async () => {
    for (const finalMode of [{ ...modes.CSP, media: otherMedia }, modes.PKCS11]) {
        const { run, calls } = scenario({ initial: container(modes.PKCS11), desired: 'CSP', finalMode });
        await assert.rejects(run, /Итоговый контейнер создан на другом/);
        assert.ok(!calls.some(([name]) => name === 'remove'));
    }
});

test('recovers the serial when only the container Media has the token ID', async () => {
    const { run, calls } = scenario({
        initial: { ...modes.CSP, id: 'opaque', fqcn: 'opaque-fqcn' }, desired: 'CSP',
    });
    assert.equal((await run()).serialNumber, serialNumber);
    assert.equal(calls.find(([name]) => name === 'Определён выбранный токен')[1].source, 'Media контейнера');
});

test('recovers the serial from an unambiguous matching reader only', async () => {
    const { run, calls } = scenario({
        initial: { reader: 'Selected reader nickname', id: 'opaque' },
        readers: [{ ...modes.CSP, label: 'Selected reader nickname' }, other],
        desired: 'CSP',
    });
    assert.equal((await run()).serialNumber, serialNumber);
    assert.equal(calls.find(([name]) => name === 'Определён выбранный токен')[1].source, 'Media считывателя');
});

test('another reader or multiple modes for the selected reader cannot determine the format', async () => {
    for (const readers of [[other], [modes.CSP, { ...modes.PKCS11, reader: modes.CSP.reader }]]) {
        const { run, calls } = scenario({
            initial: { reader: modes.CSP.reader, id: 'opaque', fqcn: 'opaque-fqcn' }, readers, desired: 'CSP',
        });
        await assert.rejects(run, /Не удалось однозначно определить/);
        assert.ok(calls.some(([name, details]) => name === 'Ответ GetReaderModes' && 'matches' in details));
        assert.ok(!calls.some(([name]) => name.startsWith('Мок POST') || name === 'remove'));
    }
});

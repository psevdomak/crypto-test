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

function scenario({ initial, desired, finalMode = modes[desired], readers, readerFormats, isWindows, generateError, removeError }) {
    const calls = [];
    const adapter = {
        async generate(name, subject, target) {
            calls.push(['generate', name, subject, target]);
            if (target?.keyFormat && generateError) throw generateError;
            return target?.keyFormat ? container(finalMode, 'new-csr') : { csr: 'initial-csr', ...initial };
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
        adapter, mockFormat: desired, name: 'reissue-test', readerFormats, isWindows,
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
        assert.deepEqual(changes[0], ['generate', 'reissue-test', 'CN=CryptoPro reissue test', { readerFormats: ['CSP', 'PKCS11'] }]);
        assert.deepEqual(changes[1], [
            'generate', 'reissue-test-final', 'CN=CryptoPro reissue test',
            { keyFormat: format, ...modes[format] },
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

test('API failures keep the initial CSR and key in the selected format', async () => {
    for (const format of Object.keys(modes)) {
        for (const desired of ['error', 'unsupported']) {
            const { run, calls } = scenario({ initial: container(modes[format]), desired });
            assert.deepEqual(await run(), { csr: 'initial-csr', regenerated: false, serialNumber });
            const changes = calls.filter(([name]) => name === 'generate' || name === 'remove');
            assert.equal(changes.length, 1);
            assert.match(calls.at(-1)[1].error, desired === 'error' ? /HTTP 503/ : /Неизвестный формат/);
            assert.equal(calls.at(-1)[1].keyFormat, format);
        }
    }
});

test('other hardware and software media skip the API and keep the first CSR', async () => {
    for (const initial of [
        { id: 'SCARD\\other_vendor_3a5a7554\\key', reader: 'Other Token' },
        { id: 'HDIMAGE\\key', reader: 'HDIMAGE', media: 'NO_UNIQUE' },
        { id: 'opaque', reader: 'Other Token' },
    ]) {
        const { run, calls } = scenario({ initial, desired: 'PKCS11' });
        assert.deepEqual(await run(), { csr: 'initial-csr', regenerated: false });
        assert.equal(calls.filter(([name]) => name === 'generate').length, 1);
        assert.ok(!calls.some(([name]) => name.startsWith('Мок POST') || name === 'remove'));
    }
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

test('a recognizable Rutoken with an unknown serial never reaches the mock', async () => {
    for (const id of ['SCARD\\rutoken_fkc_unknown\\key', 'SCARD\\rutoken_ecp_00000001\\key']) {
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
            initial: { reader: modes.CSP.reader, id: 'opaque', media: 'rutoken_ecp', fqcn: 'opaque-fqcn' },
            readers, desired: 'CSP',
        });
        await assert.rejects(run, /Не удалось однозначно определить/);
        assert.ok(calls.some(([name, details]) => name === 'Ответ GetReaderModes' && 'matches' in details));
        assert.ok(!calls.some(([name]) => name.startsWith('Мок POST') || name === 'remove'));
    }
});

test('the filter restricts the first generation while the API controls the final format', async () => {
    const initial = container(modes.PKCS11);
    const readerFormats = ['PKCS11'];
    const { run, calls } = scenario({ initial, desired: 'CSP', readerFormats });
    assert.deepEqual(await run(), { csr: 'new-csr', regenerated: true, serialNumber });
    assert.deepEqual(calls.filter(([name]) => name === 'generate'), [
        ['generate', 'reissue-test', 'CN=CryptoPro reissue test', { readerFormats }],
        ['generate', 'reissue-test-final', 'CN=CryptoPro reissue test', { keyFormat: 'CSP', ...modes.CSP }],
    ]);
});

test('FKS cannot be requested in ReaderFilter', async () => {
    const { run, calls } = scenario({ initial: container(modes.CSP), desired: 'CSP', readerFormats: ['FKS'] });
    await assert.rejects(run, /поддерживает только CSP и PKCS#11/);
    assert.deepEqual(calls, []);
});

test('a native picker that allows an excluded mode cannot produce a result', async () => {
    const initial = container({ reader: 'A FKS', media: 'rutoken_fkc_3a5a7554' });
    for (const readerFormats of [[], ['CSP', 'PKCS11']]) {
        const { run, calls } = scenario({ initial, desired: 'CSP', readerFormats });
        await assert.rejects(run, /КриптоПро создал контейнер в режиме FKS/);
        assert.deepEqual(calls[0][3], { readerFormats: ['CSP', 'PKCS11'] });
        assert.equal(calls.filter(([name]) => name === 'generate').length, 1);
        assert.ok(!calls.some(([name]) => name.startsWith('Мок POST') || name === 'remove'));
    }
});

test('Windows uses CSP for the first generation when the user selected zero or two modes', async () => {
    for (const readerFormats of [[], ['CSP', 'PKCS11']]) {
        const { run, calls } = scenario({
            initial: container(modes.CSP), desired: 'PKCS11', readerFormats, isWindows: true,
        });
        assert.deepEqual(await run(), { csr: 'new-csr', regenerated: true, serialNumber });
        const generations = calls.filter(([name]) => name === 'generate');
        assert.deepEqual(generations[0][3], { readerFormats: ['CSP'] });
        assert.deepEqual(generations[1][3], { keyFormat: 'PKCS11', ...modes.PKCS11 });
    }
});

test('Windows honors a single selected filter', async () => {
    const readerFormats = ['PKCS11'];
    const { run, calls } = scenario({
        initial: container(modes.PKCS11), desired: 'PKCS11', readerFormats, isWindows: true,
    });
    assert.equal((await run()).csr, 'initial-csr');
    assert.deepEqual(calls[0][3], { readerFormats });
});

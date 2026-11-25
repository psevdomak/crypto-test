import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequestWithKeyFormat } from './flow.mjs';
import { KeyFormat } from './key-format.mjs';

const SERIAL = '979006804';
const CSP_MEDIA = 'rutoken_ecp_3a5a7554';
const PKCS11_MEDIA = 'pkcs11_rutoken_ecp_3a5a7554';
const OTHER_MEDIA = 'rutoken_ecp_3a5a7555';

const cspMode = { reader: 'A CSP', media: CSP_MEDIA };
const pkcs11Mode = { reader: 'A PKCS#11', media: PKCS11_MEDIA };
const otherMode = { reader: 'B CSP', media: OTHER_MEDIA };

const container = (media, csr, reader = 'reader', key = 'key') => ({
    payload: { certificateRequest: csr },
    containerId: 'SCARD\\' + media + '\\' + key,
    reader,
});

function scenario({ first, api, second, readers, readersError, createError, deleteError }) {
    const calls = [];
    const logged = [];
    const loggedParams = [];
    const flow = {
        async createRequest(name, target) {
            calls.push(['create', name, target?.keyFormat ?? '']);

            if (!target) return first;
            if (createError) throw createError;

            return (
                second ??
                container(
                    target.keyFormat === KeyFormat.Csp ? CSP_MEDIA : PKCS11_MEDIA,
                    'second-csr',
                    target.reader,
                    'second',
                )
            );
        },
        async readReaders() {
            calls.push(['readReaders']);
            if (readersError) throw readersError;

            return readers ?? [cspMode, pkcs11Mode, otherMode];
        },
        async deleteContainer(containerId) {
            calls.push(['delete', containerId]);

            if (deleteError) throw deleteError;
        },
        async requestKeyFormat(serialNumber) {
            calls.push(['api', serialNumber]);

            if (api === 'error') throw new Error('HTTP 503');

            return api;
        },
        logError(method, error, params) {
            logged.push(method);
            loggedParams.push({ method, error: error?.message ?? String(error), ...params });
        },
    };

    return {
        run: () => createRequestWithKeyFormat(flow, 'reissue'),
        calls,
        logged,
        loggedParams,
        ids: (action) => calls.filter(([a]) => a === action),
    };
}

const firstCsp = () => container(CSP_MEDIA, 'first-csr');
const firstPkcs11 = () => container(PKCS11_MEDIA, 'first-csr');

for (const [format, make] of [
    [KeyFormat.Csp, firstCsp],
    [KeyFormat.Pkcs11, firstPkcs11],
]) {
    test(
        'Если API подтвердил формат ' + format + ', то остаётся первый контейнер и его CSR',
        async () => {
            const first = make();
            const { run, calls, ids } = scenario({ first, api: format });

            assert.deepEqual(await run(), { payload: first.payload, regenerated: false });
            assert.ok(calls.some(([action, serial]) => action === 'api' && serial === SERIAL));
            assert.equal(ids('create').length, 1);
            assert.equal(ids('delete').length, 0);
        },
    );
}

for (const [format, make] of [
    [KeyFormat.Csp, firstPkcs11],
    [KeyFormat.Pkcs11, firstCsp],
]) {
    test(
        'Если API вернул другой формат (' + format + '), то второй контейнер на том же токене, первый удаляется',
        async () => {
            const first = make();
            const { run, ids } = scenario({ first, api: format });

            assert.deepEqual(await run(), {
                payload: { certificateRequest: 'second-csr' },
                regenerated: true,
            });
            assert.deepEqual(ids('create'), [
                ['create', 'reissue', ''],
                ['create', 'reissue', format],
            ]);
            assert.deepEqual(ids('delete'), [['delete', first.containerId]]);
        },
    );
}

for (const api of ['error', 'unknown']) {
    test('Если API ответил «' + api + '», то остаётся первый CSR', async () => {
        const first = firstPkcs11();
        const { run, ids, logged } = scenario({ first, api });

        assert.deepEqual(await run(), { payload: first.payload, regenerated: false });
        assert.equal(ids('create').length, 1);
        assert.equal(ids('delete').length, 0);
        assert.deepEqual(
            logged,
            api === 'error' ? ['requestKeyFormat'] : ['requestKeyFormat:unknown'],
        );
    });
}

for (const [index, first] of [
    container('other_vendor_3a5a7554', 'first-csr'),
    {
        ...container('HDIMAGE', 'first-csr'),
        containerId: 'HDIMAGE\\key',
        reader: 'HDIMAGE',
    },
].entries()) {
    test('Если носитель не Рутокен, то API не вызывается (' + index + ')', async () => {
        const { run, ids } = scenario({ first, api: KeyFormat.Pkcs11 });

        assert.deepEqual(await run(), { payload: first.payload, regenerated: false });
        assert.equal(ids('api').length, 0);
    });
}

test('Если первый контейнер создан в режиме FKS, то он удаляется, API не вызывается', async () => {
    const first = container('rutoken_fkc_3a5a7554', 'first-csr');
    const { run, ids } = scenario({ first, api: KeyFormat.Csp });

    await assert.rejects(run, /в режиме FKS/);
    assert.equal(ids('api').length, 0);
    assert.deepEqual(ids('delete'), [['delete', first.containerId]]);
});

test('Если первый контейнер не идентифицируется, то он удаляется, ошибка пробрасывается', async () => {
    const first = container('rutoken_ecp3_3a5a7554', 'first-csr', 'Rutoken ECP 0');
    const { run, ids } = scenario({ first, api: KeyFormat.Csp });

    await assert.rejects(run, /однозначно определить/);
    assert.equal(ids('api').length, 0);
    assert.deepEqual(ids('delete'), [['delete', first.containerId]]);
});

test('Если итоговый контейнер не идентифицируется, то он удаляется, ошибка пробрасывается', async () => {
    const second = container(
        'rutoken_ecp3_3a5a7554',
        'second-csr',
        'Rutoken ECP 0',
        'second',
    );
    const { run, ids } = scenario({
        first: firstPkcs11(),
        api: KeyFormat.Csp,
        second,
    });

    await assert.rejects(run, /однозначно определить/);
    assert.deepEqual(ids('delete'), [['delete', second.containerId]]);
});

test('Одинаковые записи CSP-считывателя считаются одним вариантом', async () => {
    const { run } = scenario({
        first: firstPkcs11(),
        api: KeyFormat.Csp,
        readers: [pkcs11Mode, cspMode, { ...cspMode }, otherMode],
    });

    assert.deepEqual(await run(), {
        payload: { certificateRequest: 'second-csr' },
        regenerated: true,
    });
});

for (const { options, reason } of [
    { options: { readers: [pkcs11Mode, otherMode] }, reason: 'считыватель не найден' },
    {
        options: { readers: [pkcs11Mode, cspMode, { ...cspMode, reader: 'A second CSP' }] },
        reason: 'найдено несколько считывателей (2)',
    },
    { options: { readersError: new Error('GetReaderModes failed') }, reason: 'GetReaderModes failed' },
]) {
    test(
        'Если подготовка второй генерации не удалась, причина логируется и возвращается первый CSR: ' + reason,
        async () => {
            const first = firstPkcs11();
            const { run, ids, loggedParams } = scenario({ first, api: KeyFormat.Csp, ...options });

            assert.deepEqual(await run(), { payload: first.payload, regenerated: false });
            assert.equal(ids('create').length, 1);
            assert.equal(ids('delete').length, 0);
            const entry = loggedParams.find(
                ({ method }) => method === 'createRequestWithKeyFormat:createSecond',
            );
            assert.ok(entry.error.includes(reason));
            assert.equal(entry.serialNumber, SERIAL);
            assert.deepEqual(entry.readerModes, options.readers);
        },
    );
}

test('Если вторая генерация упала, то возвращается CSR первого контейнера, ошибка логируется', async () => {
    const first = firstPkcs11();
    const { run, ids, logged } = scenario({
        first,
        api: KeyFormat.Csp,
        createError: new Error('CreateRequest failed'),
    });

    assert.deepEqual(await run(), { payload: first.payload, regenerated: false });
    assert.equal(ids('delete').length, 0);
    assert.ok(logged.includes('createRequestWithKeyFormat:createSecond'));
});

for (const [index, createError] of [
    new Error('Отмена пользователем (0x8010006E)'),
    Object.assign(new Error('Canceled'), { code: '0x8010006E' }),
    Object.assign(new Error('Canceled'), { number: -2146434962 }),
    Object.assign(new Error('Canceled'), { number: 0x8010006e }),
    Object.assign(new Error('Canceled'), { code: '-2146434962' }),
].entries()) {
    test(
        'Если пользователь отменил вторую генерацию, то первый контейнер удаляется, исходная ошибка пробрасывается (' + index + ')',
        async () => {
            const first = firstPkcs11();
            const { run, ids, logged } = scenario({ first, api: KeyFormat.Csp, createError });

            await assert.rejects(run, (error) => error === createError);
            assert.deepEqual(ids('delete'), [['delete', first.containerId]]);
            assert.ok(logged.includes('createRequestWithKeyFormat:createSecond'));
        },
    );
}

test('Если ошибка с другим HRESULT, то это не отмена: возвращается CSR первого контейнера', async () => {
    const first = firstPkcs11();
    const { run, ids } = scenario({
        first,
        api: KeyFormat.Csp,
        createError: Object.assign(new Error('No readers'), { number: -2146435026 }),
    });

    assert.deepEqual(await run(), { payload: first.payload, regenerated: false });
    assert.equal(ids('delete').length, 0);
});

for (const containerId of [undefined, null]) {
    test('Если id итогового контейнера не строка (' + containerId + '), то первый сохраняется, в лог пишется причина', async () => {
        const { run, ids, logged } = scenario({
            first: firstPkcs11(),
            api: KeyFormat.Csp,
            second: { ...container(CSP_MEDIA, 'second-csr', 'A CSP'), containerId },
        });

        await assert.rejects(run, /не вернул уникальное имя/);
        assert.equal(ids('delete').length, 0);
        assert.ok(logged.includes('createRequestWithKeyFormat:emptySecondId'));
    });
}

test('Если после отмены не удалось удалить первый контейнер, то отмена не подменяется, сбой логируется', async () => {
    const createError = new Error('Отмена пользователем (0x8010006E)');
    const { run, logged } = scenario({
        first: firstPkcs11(),
        api: KeyFormat.Csp,
        createError,
        deleteError: new Error('Delete failed'),
    });

    await assert.rejects(run, (error) => error === createError);
    assert.ok(logged.includes('deleteContainer'));
});

test('Если удаление итогового контейнера упало, то ошибка сверки не подменяется, сбой логируется', async () => {
    const second = container(PKCS11_MEDIA, 'second-csr', 'A CSP', 'second');
    const { run, logged } = scenario({
        first: firstPkcs11(),
        api: KeyFormat.Csp,
        second,
        deleteError: new Error('Delete failed'),
    });

    await assert.rejects(run, /на другом токене или в другом формате/);
    assert.deepEqual(logged, [
        'createRequestWithKeyFormat:secondContainer',
        'createRequestWithKeyFormat:verifySecond',
        'deleteContainer',
    ]);
});

for (const [index, second] of [
    container(OTHER_MEDIA, 'second-csr', 'A CSP', 'second'),
    container(PKCS11_MEDIA, 'second-csr', 'A CSP', 'second'),
].entries()) {
    test(
        'Если итоговый контейнер на другом токене или в другом формате, то он удаляется, первый сохраняется (' +
            index +
            ')',
        async () => {
            const first = firstPkcs11();
            const { run, ids } = scenario({ first, api: KeyFormat.Csp, second });

            await assert.rejects(run, /на другом токене или в другом формате/);
            assert.deepEqual(ids('delete'), [['delete', second.containerId]]);
        },
    );
}

test('При совпадении id контейнер сохраняется, повторная сверка считывателя пропускается', async () => {
    const first = { ...firstPkcs11(), containerId: 'opaque-id', reader: pkcs11Mode.reader };
    const { run, ids, logged } = scenario({
        first,
        api: KeyFormat.Csp,
        second: {
            ...container(CSP_MEDIA, 'second-csr', cspMode.reader),
            containerId: first.containerId,
        },
    });

    await assert.rejects(run, /КриптоПро вернул тот же контейнер/);
    assert.equal(ids('readReaders').length, 2);
    assert.equal(ids('delete').length, 0);
    assert.ok(logged.includes('createRequestWithKeyFormat:verifySecond'));
});

test('Если у итогового контейнера нет id, первый сохраняется и CSR не возвращается', async () => {
    const { run, ids, logged } = scenario({
        first: firstPkcs11(),
        api: KeyFormat.Csp,
        second: { ...container(CSP_MEDIA, 'second-csr', 'A CSP'), containerId: '' },
    });

    await assert.rejects(run, /не вернул уникальное имя итогового контейнера/);
    assert.equal(ids('delete').length, 0);
    assert.ok(logged.includes('createRequestWithKeyFormat:emptySecondId'));
});

test('Если удалить первый контейнер не удалось, то сообщается, что итоговый уже создан', async () => {
    const { run, ids } = scenario({
        first: firstPkcs11(),
        api: KeyFormat.Csp,
        deleteError: new Error('Delete failed'),
    });

    await assert.rejects(
        run,
        /Итоговый контейнер создан, но удалить первоначальный не удалось\. Delete failed/,
    );
    assert.equal(ids('create').length, 2);
});

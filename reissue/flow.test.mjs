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
        logError(method) {
            logged.push(method);
        },
    };

    return {
        run: () => createRequestWithKeyFormat(flow, 'reissue'),
        calls,
        logged,
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

for (const [options, errorPattern] of [
    [{ readers: [pkcs11Mode, otherMode] }, /считыватель CSP не найден/],
    [
        { readers: [pkcs11Mode, cspMode, { ...cspMode, reader: 'A second CSP' }] },
        /считыватель CSP определён неоднозначно/,
    ],
    [{ readersError: new Error('GetReaderModes failed') }, /GetReaderModes failed/],
]) {
    test(
        'Если подготовка второй генерации не удалась, то ошибка пробрасывается: ' + errorPattern.source,
        async () => {
            const first = firstPkcs11();
            const { run, ids, logged } = scenario({ first, api: KeyFormat.Csp, ...options });

            await assert.rejects(run, errorPattern);
            assert.equal(ids('create').length, 1);
            assert.equal(ids('delete').length, 0);
            assert.ok(logged.includes('createRequestWithKeyFormat:findTargetReader'));
        },
    );
}

for (const createError of [
    new Error('CreateRequest failed'),
    new Error('Отмена пользователем (0x8010006E)'),
]) {
    test(
        'Если вторая генерация упала, то первый контейнер удаляется и пробрасывается ошибка: ' +
            createError.message,
        async () => {
            const first = firstPkcs11();
            const { run, ids, logged } = scenario({
                first,
                api: KeyFormat.Csp,
                createError,
            });

            await assert.rejects(run, (error) => error === createError);
            assert.deepEqual(ids('delete'), [['delete', first.containerId]]);
            assert.ok(logged.includes('createRequestWithKeyFormat:createSecond'));
        },
    );
}

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

test('Если итоговый контейнер имеет тот же id, что первый, то ничего не удаляется', async () => {
    const first = firstPkcs11();
    const { run, ids } = scenario({
        first,
        api: KeyFormat.Csp,
        second: {
            ...container(CSP_MEDIA, 'second-csr'),
            containerId: first.containerId,
        },
    });

    await assert.rejects(run);
    assert.equal(ids('delete').length, 0);
});

test('Если у итогового контейнера нет id, первый сохраняется и CSR не возвращается', async () => {
    const { run, ids } = scenario({
        first: firstPkcs11(),
        api: KeyFormat.Csp,
        second: { ...container(CSP_MEDIA, 'second-csr', 'A CSP'), containerId: '' },
    });

    await assert.rejects(run, /не вернул уникальное имя итогового контейнера/);
    assert.equal(ids('delete').length, 0);
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

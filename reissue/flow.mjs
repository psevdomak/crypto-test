const mockPath = '/api/v1/company/test/common/key-format';

function mockKeyFormat(keyFormat) {
    return async (request) => {
        if (request.method !== 'POST' || new URL(request.url).pathname !== mockPath) {
            return new Response(null, { status: 404 });
        }
        const { serialNumber } = await request.json();
        if (typeof serialNumber !== 'string' || !serialNumber.trim()) {
            return new Response(null, { status: 400 });
        }
        if (keyFormat === 'error') {
            return new Response(null, { status: 503 });
        }
        return Response.json({ keyFormat });
    };
}

function sameReader(actual, expected) {
    return actual.reader === expected.reader && actual.media === expected.media;
}

function verifyReader(readers, expected) {
    const matches = readers.filter(({ reader }) => reader === expected.reader);
    if (matches.length !== 1 || !expected.media || !sameReader(matches[0], expected)) {
        throw new Error('Считыватель отсутствует или его Media изменилось: ' + expected.reader);
    }
}

export async function reissue({ adapter, modes, serialNumber, mockFormat, name, subject, report }) {
    const initial = await adapter.generate(name, subject);
    const initialFormat = Object.keys(modes).find((format) => sameReader(initial, modes[format]));
    if (!initialFormat) {
        throw new Error('Первый контейнер не совпал ни с одним контрольным считывателем.');
    }
    const readers = await adapter.readers();
    verifyReader(readers, modes[initialFormat]);

    const request = new Request('https://mock.invalid' + mockPath, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ serialNumber }),
    });
    report('Мок POST ' + mockPath, { serialNumber });
    const response = await mockKeyFormat(mockFormat)(request);
    if (!response.ok) {
        throw new Error('Мок API вернул HTTP ' + response.status);
    }
    const { keyFormat } = await response.json();
    report('Ответ мок API', { keyFormat, initialFormat });

    if (keyFormat !== 'CSP' && keyFormat !== 'PKCS11') {
        throw new Error('Неизвестный формат ключей.');
    }
    if (keyFormat === initialFormat) {
        return { csr: initial.csr, regenerated: false };
    }

    const target = modes[keyFormat];
    if (!target) {
        throw new Error('Укажите контрольный считыватель для ' + keyFormat);
    }
    verifyReader(readers, target);
    await adapter.remove(initial);
    verifyReader(await adapter.readers(), target);
    const final = await adapter.generate(name, subject, { keyFormat, reader: target.reader });
    if (!sameReader(final, target)) {
        throw new Error('Итоговый контейнер не совпал с контрольным считывателем и Media.');
    }
    verifyReader(await adapter.readers(), target);
    return { csr: final.csr, regenerated: true };
}

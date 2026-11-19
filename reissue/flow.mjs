const mockPath = '/api/v1/company/test/common/key-format';

function mockKeyFormat(keyFormat) {
    return async (request) => {
        if (request.method !== 'POST' || new URL(request.url).pathname !== mockPath) {
            return new Response(null, { status: 404 });
        }
        const { serialNumber } = await request.json();
        if (typeof serialNumber !== 'string' || !/^\d{8,10}$/.test(serialNumber)) {
            return new Response(null, { status: 400 });
        }
        if (keyFormat === 'error') {
            return new Response(null, { status: 503 });
        }
        return Response.json({ keyFormat });
    };
}

// CryptoPro reports the same hexadecimal serial in both ECP media names.
// https://cryptopro.ru/forum2/default.aspx?g=posts&t=24912
// https://cryptopro.ru/forum2/default.aspx?g=posts&t=11386
function rutokenIdentity(media) {
    if (typeof media !== 'string') return undefined;
    const match = /^(rutoken_ecp|pkcs11_rutoken_ecp|rutoken_lt)_([\da-f]{8})$/i.exec(media);
    if (!match) return undefined;

    const prefix = match[1].toLowerCase();
    const serialNumber = Number.parseInt(match[2], 16).toString(10);
    if (!/^\d{8,10}$/.test(serialNumber)) return undefined;

    return {
        serialNumber,
        family: prefix === 'rutoken_lt' ? 'Lite' : 'ECP',
        keyFormat: prefix === 'pkcs11_rutoken_ecp' ? 'PKCS11' : 'CSP',
    };
}

function containerIdentity(path) {
    if (typeof path !== 'string') return undefined;
    const parts = path.split('\\');
    // An FQCN may prefix the unique path with the reader as \\.\Reader.
    const start = path.startsWith('\\\\.\\') ? 4 : 0;
    if (parts[start]?.toUpperCase() !== 'SCARD' || !parts[start + 2]) return undefined;
    return rutokenIdentity(parts[start + 1]);
}

function sameToken(first, second) {
    return first && first.serialNumber === second.serialNumber && first.family === second.family;
}

function identifyContainer(container) {
    const fromId = containerIdentity(container.id);
    const fromFqcn = containerIdentity(container.fqcn);
    const token = fromId ?? fromFqcn;
    if (!token) {
        throw new Error('В имени созданного контейнера не найден серийный номер Рутокена из 8–10 цифр.');
    }
    if (fromId && fromFqcn && (!sameToken(fromId, fromFqcn) || fromId.keyFormat !== fromFqcn.keyFormat)) {
        throw new Error('UniqueName и FQCN указывают на разные токены или форматы.');
    }
    const fromMedia = rutokenIdentity(container.media);
    if (fromMedia && !sameToken(fromMedia, token)) {
        throw new Error('Media контейнера указывает на другой токен.');
    }
    return token;
}

function findTarget(readers, token, keyFormat) {
    const names = new Set();
    for (const { reader, media } of readers) {
        const identity = rutokenIdentity(media);
        if (reader && sameToken(identity, token) && identity.keyFormat === keyFormat) {
            names.add(reader);
        }
    }
    const [name] = names;
    const sharedName = readers.some(({ reader, media }) => {
        if (reader !== name) return false;
        const identity = rutokenIdentity(media);
        return identity?.keyFormat === keyFormat && !sameToken(identity, token);
    });
    if (names.size !== 1 || sharedName) {
        throw new Error('Для Рутокена ' + token.serialNumber + ' считыватель ' + keyFormat
            + ' отсутствует или найден неоднозначно.');
    }
    return name;
}

export async function reissue({ adapter, mockFormat, name, subject, report }) {
    const initial = await adapter.generate(name, subject);
    const token = identifyContainer(initial);
    const { serialNumber, keyFormat: initialFormat } = token;
    report('Определён выбранный токен', { ...token, reader: initial.reader });

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
        return { csr: initial.csr, regenerated: false, serialNumber };
    }

    const readers = await adapter.readers();
    report('Режимы считывателей перед повторной генерацией', readers);
    const reader = findTarget(readers, token, keyFormat);
    await adapter.remove(initial);
    if (findTarget(await adapter.readers(), token, keyFormat) !== reader) {
        throw new Error('Целевой считыватель изменился после удаления контейнера.');
    }
    const final = await adapter.generate(name, subject, { keyFormat, reader });
    const finalToken = identifyContainer(final);
    report('Проверка итогового контейнера', finalToken);
    if (!sameToken(finalToken, token) || finalToken.keyFormat !== keyFormat || final.reader !== reader) {
        throw new Error('Итоговый контейнер создан на другом считывателе, токене или в другом формате.');
    }
    return { csr: final.csr, regenerated: true, serialNumber };
}

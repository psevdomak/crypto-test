const mockPath = '/api/v1/company/test/common/key-format';
const subject = 'CN=CryptoPro reissue test';

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
    const match = /^(rutoken_ecp|pkcs11_rutoken_ecp|rutoken_lt|rutoken_fkc)_([\da-f]{8})$/i.exec(media);
    if (!match) return undefined;

    const prefix = match[1].toLowerCase();
    const serialNumber = Number.parseInt(match[2], 16).toString(10);
    if (!/^\d{8,10}$/.test(serialNumber)) return undefined;

    return {
        serialNumber,
        family: prefix === 'rutoken_lt' ? 'Lite' : 'ECP',
        keyFormat: { pkcs11_rutoken_ecp: 'PKCS11', rutoken_fkc: 'FKS' }[prefix] ?? 'CSP',
    };
}

function containerMediaName(path) {
    if (typeof path !== 'string') return undefined;
    const parts = path.split('\\');
    // An FQCN may prefix the unique path with the reader as \\.\Reader.
    const start = path.startsWith('\\\\.\\') ? 4 : 0;
    if (parts[start]?.toUpperCase() !== 'SCARD' || !parts[start + 2]) return undefined;
    return parts[start + 1];
}

function sameToken(first, second) {
    return first && first.serialNumber === second.serialNumber && first.family === second.family;
}

async function identifyContainer(container, adapter, report) {
    const { id, fqcn, reader, media } = container;
    const idMedia = containerMediaName(id);
    const fqcnMedia = containerMediaName(fqcn);
    const fromId = rutokenIdentity(idMedia);
    const fromFqcn = rutokenIdentity(fqcnMedia);
    const fromMedia = rutokenIdentity(media);
    const fromPath = fromId ?? fromFqcn;
    if (fromId && fromFqcn && (!sameToken(fromId, fromFqcn) || fromId.keyFormat !== fromFqcn.keyFormat)) {
        throw new Error('UniqueName и FQCN указывают на разные токены или форматы.');
    }
    if (fromPath && fromMedia && !sameToken(fromMedia, fromPath)) {
        throw new Error('Media контейнера указывает на другой токен.');
    }
    if (fromPath || fromMedia) {
        const source = fromId ? 'UniqueName' : fromFqcn ? 'FQCN' : 'Media контейнера';
        return { ...(fromPath ?? fromMedia), source };
    }

    const rutoken = (value) => typeof value === 'string' && /rutoken/i.test(value);
    let hasRutokenEvidence = [idMedia, fqcnMedia, reader, media].some(rutoken);
    if (!hasRutokenEvidence && (idMedia || fqcnMedia)) return undefined;

    report('Поиск серийного номера по считывателю', { uniqueName: id, fqcn, reader, media });
    if (reader) {
        let modes;
        try {
            modes = await adapter.readers();
        } catch (error) {
            report('GetReaderModes недоступен', error.message || String(error));
            if (!hasRutokenEvidence) return undefined;
            throw error;
        }
        const matches = modes.filter((mode) => mode.reader === reader || mode.label === reader);
        report('Ответ GetReaderModes', { matches, ...(matches.length ? {} : { available: modes }) });
        const activeModes = matches.filter((mode) => mode.media !== 'NO_MEDIA');
        const identities = activeModes.map((mode) => rutokenIdentity(mode.media));
        const [token] = identities;
        if (token && identities.every((identity) => sameToken(identity, token)
            && identity.keyFormat === token.keyFormat)) {
            return { ...token, source: 'Media считывателя' };
        }
        hasRutokenEvidence ||= matches.some((mode) => [mode.reader, mode.label, mode.media].some(rutoken));
    }

    if (!hasRutokenEvidence) return undefined;
    throw new Error('Не удалось однозначно определить серийный номер Рутокена из 8–10 цифр и режим. См. данные контейнера и считывателей в журнале.');
}

function findTarget(readers, token, keyFormat) {
    const targets = new Map();
    for (const { reader, media } of readers) {
        const identity = rutokenIdentity(media);
        if (reader && sameToken(identity, token) && identity.keyFormat === keyFormat) {
            targets.set(reader, { reader, media });
        }
    }
    const [target] = targets.values();
    const sharedName = readers.some((mode) => {
        if (mode.reader !== target?.reader) return false;
        const identity = rutokenIdentity(mode.media);
        return identity?.keyFormat === keyFormat && !sameToken(identity, token);
    });
    if (targets.size !== 1 || sharedName) {
        throw new Error('Для Рутокена ' + token.serialNumber + ' считыватель ' + keyFormat
            + ' отсутствует или найден неоднозначно.');
    }
    return target;
}

async function requestKeyFormat(mockFormat, serialNumber, report) {
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
    if (keyFormat !== 'CSP' && keyFormat !== 'PKCS11') {
        throw new Error('Неизвестный формат ключей.');
    }
    return keyFormat;
}

export async function reissue({ adapter, mockFormat, name, readerFormats = [], report }) {
    if (readerFormats.some((format) => format !== 'CSP' && format !== 'PKCS11')) {
        throw new Error('ReaderFilter поддерживает только CSP и PKCS#11.');
    }
    const initialOptions = readerFormats.length ? { readerFormats } : undefined;
    const initial = await adapter.generate(name, subject, initialOptions);
    const token = await identifyContainer(initial, adapter, report);
    if (!token) {
        report('Носитель не распознан как Рутокен. Использован первый контейнер.');
        return { csr: initial.csr, regenerated: false };
    }
    const { serialNumber, keyFormat: initialFormat } = token;
    report('Определён выбранный токен', { ...token, reader: initial.reader });
    const allowedFormats = readerFormats.length ? readerFormats : ['CSP', 'PKCS11'];
    if (!allowedFormats.includes(initialFormat)) {
        throw new Error('КриптоПро создал контейнер в режиме ' + initialFormat
            + '. Разрешённые режимы первой генерации: ' + allowedFormats.join(', ') + '.');
    }

    let keyFormat;
    try {
        keyFormat = await requestKeyFormat(mockFormat, serialNumber, report);
    } catch (error) {
        report('Не удалось получить формат от API. Использован выбранный формат.', {
            keyFormat: initialFormat,
            error: error.message || String(error),
        });
        return { csr: initial.csr, regenerated: false, serialNumber };
    }
    report('Ответ мок API', { keyFormat, initialFormat });
    if (keyFormat === initialFormat) {
        return { csr: initial.csr, regenerated: false, serialNumber };
    }

    const readers = await adapter.readers();
    report('Режимы считывателей перед повторной генерацией', readers);
    const target = findTarget(readers, token, keyFormat);
    const final = await adapter.generate(name + '-final', subject, { keyFormat, ...target });
    const finalToken = await identifyContainer(final, adapter, report);
    report('Проверка итогового контейнера', finalToken);
    if (!sameToken(finalToken, token) || finalToken.keyFormat !== keyFormat || final.reader !== target.reader) {
        throw new Error('Итоговый контейнер создан на другом считывателе, токене или в другом формате.');
    }
    if (final.id === initial.id) {
        throw new Error('Итоговый и первоначальный контейнеры имеют одинаковый идентификатор.');
    }

    try {
        await adapter.remove(initial);
    } catch (error) {
        throw new Error('Итоговый контейнер создан, но удалить первоначальный не удалось. '
            + (error.message || String(error)), { cause: error });
    }
    return { csr: final.csr, regenerated: true, serialNumber };
}

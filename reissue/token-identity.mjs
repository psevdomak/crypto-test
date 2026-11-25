import {KeyFormat} from './key-format.mjs';

const SERIAL_PATTERN = /^\d{8,10}$/;
// Media-имя Рутокена: `<pkcs11_>rutoken_<модель>_<серийный номер в hex>`.
// Модель `lt` — семейство Lite, префикс `pkcs11_` — режим PKCS#11, модель `fkc` — FKS.
const RUTOKEN_MEDIA_PATTERN = /^(pkcs11_)?rutoken_(ecp|lt|fkc)_([\da-f]{8})$/i;

function keyFormatFrom(pkcs11, model) {
    if (pkcs11) return KeyFormat.Pkcs11;
    if (model === 'fkc') return KeyFormat.Fks;

    return KeyFormat.Csp;
}

export function rutokenIdentity(media) {
    if (typeof media !== 'string') return undefined;

    const match = RUTOKEN_MEDIA_PATTERN.exec(media);

    if (!match) return undefined;

    const [, pkcs11, rawModel, hexSerial] = match;
    const model = rawModel.toLowerCase();
    const serialNumber = Number.parseInt(hexSerial, 16).toString(10);

    if (!SERIAL_PATTERN.test(serialNumber)) return undefined;

    return {
        serialNumber,
        family: model === 'lt' ? 'Lite' : 'ECP',
        keyFormat: keyFormatFrom(pkcs11, model),
    };
}

/** Media-имя носителя из пути контейнера `SCARD\<media>\...` (в т.ч. с префиксом считывателя). */
export function tokenMedia(containerName) {
    if (!containerName) return undefined;

    const parts = containerName.split('\\');
    const start = containerName.startsWith('\\\\.\\') ? 4 : 0;

    return parts[start]?.toUpperCase() === 'SCARD' ? parts[start + 1] : undefined;
}

export function isSameToken(first, second) {
    return (
        !!first &&
        first.serialNumber === second.serialNumber &&
        first.family === second.family
    );
}

/**
 * Определяет носитель созданного контейнера по media-имени, а если его нет —
 * по режимам считывателя контейнера.
 *
 * `undefined` — носитель не Рутокен. Если признаки Рутокена есть, но серийный
 * номер или режим однозначно не определяются — ошибка: ни API, ни повторная
 * генерация не запускаются.
 */
export async function identifyToken(containerMedia, reader, readReaders) {
    const direct = rutokenIdentity(containerMedia);

    if (direct) return direct;

    const modes = reader ? await readReaders().catch(() => []) : [];
    const identities = modes
        .filter((mode) => mode.reader === reader)
        .map((mode) => rutokenIdentity(mode.media))
        .filter((identity) => Boolean(identity));
    const [token] = identities;

    if (
        token &&
        identities.every(
            (identity) =>
                isSameToken(identity, token) && identity.keyFormat === token.keyFormat,
        )
    ) {
        return token;
    }

    const looksLikeRutoken =
        identities.length > 0 ||
        [containerMedia, reader].some(
            (value) => typeof value === 'string' && /rutoken/i.test(value),
        );

    if (!looksLikeRutoken) return undefined;

    throw new Error(
        'Не удалось однозначно определить серийный номер Рутокена и режим ключа.',
    );
}

/** Единственный считыватель выбранного токена в запрошенном режиме; иначе — ошибка. */
export function findTargetReader(readers, token, keyFormat) {
    const targets = [];
    for (const {reader, media} of readers) {
        const identity = rutokenIdentity(media);
        if (!reader || !isSameToken(identity, token) || identity.keyFormat !== keyFormat) continue;

        if (!targets.some((target) => target.reader === reader && target.media === media)) {
            targets.push({reader, media});
        }
    }

    if (targets.length === 1) return targets[0];

    const detail = 'Для Рутокена ' + token.serialNumber + ' в режиме ' + keyFormat;
    throw new Error(
        targets.length === 0
            ? detail + ' считыватель не найден.'
            : detail + ' найдено несколько считывателей (' + targets.length + ').',
    );
}

import {KeyFormat} from './key-format.mjs';
import {
    findTargetReader,
    identifyToken,
    isSameToken,
    rutokenIdentity,
    tokenMedia,
} from './token-identity.mjs?v=26';

/**
 * Базовый интерфейс зависимостей соответствует KeyFormatFlow
 * из sme-qds-ui (`libs/common/crypto/src/lib/cadescom/key-format-flow.ts`).
 *
 * createRequest(name, target?) отвечает `{payload, containerId, reader}`;
 * `target` — считыватель выбранного токена и режим ключа.
 * readSmartCardReaders() перечисляет режимы смарт-карт до генерации.
 */

const isSupportedFormat = (value) =>
    value === KeyFormat.Csp || value === KeyFormat.Pkcs11;

/** Что попадает в лог о токене: без него ошибку пользователя не локализовать. */
const tokenParams = (token) => ({
    serialNumber: token.serialNumber,
    family: token.family,
    keyFormat: token.keyFormat,
});

/** Best-effort удаление: ошибка логируется и не подменяет исходную. */
async function deleteQuietly(flow, containerId) {
    try {
        await flow.deleteContainer(containerId);
    } catch (error) {
        flow.logError('deleteContainer', error, {containerId});
    }
}

/** Шаг сценария; при ошибке созданный контейнер удаляется, исходная ошибка пробрасывается. */
async function withCleanupOnError(flow, containerId, method, action, params) {
    try {
        return await action();
    } catch (error) {
        flow.logError(method, error, {...params, containerId});
        await deleteQuietly(flow, containerId);

        throw error;
    }
}

/**
 * Формат итогового ключа. `undefined` — используем обычный режим генерации
 * или сохраняем первый контейнер, если он уже создан.
 */
async function resolveKeyFormat(flow, token, useOriginalFormat = false) {
    if (!isSupportedFormat(token.keyFormat)) {
        throw new Error(
            'КриптоПро создал контейнер в режиме ' +
                token.keyFormat +
                '. Для перевыпуска подходят CSP и PKCS11.',
        );
    }
    if (useOriginalFormat) return undefined;

    try {
        const keyFormat = await flow.requestKeyFormat(token.serialNumber);

        if (!isSupportedFormat(keyFormat)) {
            flow.logError(
                'requestKeyFormat:unknown',
                'API вернул неизвестный формат ключа: ' + String(keyFormat),
                {...tokenParams(token), value: keyFormat},
            );

            return undefined;
        }

        return keyFormat;
    } catch (error) {
        flow.logError('requestKeyFormat', error, tokenParams(token));

        return undefined;
    }
}

async function prepareDirectRequest(flow) {
    let readerModes;
    try {
        readerModes = await flow.readSmartCardReaders();
    } catch (error) {
        flow.logError('createRequestWithKeyFormat:readSmartCardReaders', error);
        return undefined;
    }

    // Пустые слоты и программные носители не участвуют в выборе смарт-карты.
    const tokens = readerModes
        .filter(({media}) => !['NO_MEDIA', 'HDIMAGE', 'REGISTRY'].includes(media))
        .map(({media}) => rutokenIdentity(media));
    const token = tokens.find((entry) => isSupportedFormat(entry?.keyFormat));
    if (!token || !tokens.every((entry) => isSameToken(entry, token))) return undefined;

    const keyFormat = await resolveKeyFormat(flow, token);
    if (!keyFormat) return {token};

    try {
        const target = findTargetReader(readerModes, token, keyFormat);
        return {token, keyFormat, target};
    } catch (error) {
        flow.logError('createRequestWithKeyFormat:prepareDirect', error, {
            ...tokenParams(token),
            keyFormat,
            readerModes,
        });
        return {token};
    }
}

/** HRESULT приходит знаковым числом (`-2146434962`) — приводим к беззнаковому. */
const toUnsigned = (value) => (value < 0 ? value + 0x100000000 : value);
const CANCELED = '0x8010006E';

/**
 * Пользователь отменил действие в окне КриптоПро. Код встречается в `code`,
 * в `number` (знаковый HRESULT) и в тексте ошибки (`... (0x8010006E)`).
 */
function isCanceledByUser(error) {
    const {code, number, message} = error ?? {};
    const canceledNumber = Number(CANCELED);

    return (
        String(message ?? '').toLowerCase().includes(CANCELED.toLowerCase()) ||
        [code, number].some((value) => {
            const parsed = Number(value);

            return (
                value !== null &&
                value !== '' &&
                Number.isFinite(parsed) &&
                toUnsigned(parsed) === canceledNumber
            );
        })
    );
}

/**
 * Второй контейнер на том же токене в нужном формате. `undefined` — создать не
 * удалось (нет считывателя, ошибка драйвера): остаётся CSR первого.
 * Отмена пользователем — ошибка: первый контейнер удаляется, ошибка пробрасывается.
 */
async function createSecondRequest(flow, name, firstId, token, keyFormat) {
    let readerModes;

    try {
        readerModes = await flow.readReaders();

        const target = findTargetReader(readerModes, token, keyFormat);

        return await flow.createRequest(name, {keyFormat, ...target});
    } catch (error) {
        // Список режимов считывателей — главное для разбора «почему не нашли».
        flow.logError('createRequestWithKeyFormat:createSecond', error, {
            ...tokenParams(token),
            keyFormat,
            containerId: firstId,
            readerModes,
        });

        if (isCanceledByUser(error)) {
            await deleteQuietly(flow, firstId);

            throw error;
        }

        return undefined;
    }
}

/** Итоговый контейнер должен быть на том же токене и в нужном формате; иначе он удаляется. */
async function verifyFinalRequest(flow, finalRequest, token, keyFormat, firstId) {
    const {containerId: finalId, reader} = finalRequest;
    const stage = firstId === undefined ? 'Direct' : 'Second';
    const params = {...tokenParams(token), keyFormat, firstId, secondId: finalId};

    if (!finalId?.trim()) {
        const reason = 'КриптоПро не вернул уникальное имя итогового контейнера.';
        flow.logError(
            'createRequestWithKeyFormat:empty' + stage + 'Id',
            reason,
            params,
        );

        throw new Error(reason + ' Формат не подтверждён.');
    }

    if (finalId === firstId) {
        const reason = 'КриптоПро вернул тот же контейнер при второй генерации.';
        flow.logError('createRequestWithKeyFormat:verifySecond', reason, params);
        throw new Error(reason);
    }

    const secondToken = await withCleanupOnError(
        flow,
        finalId,
        'createRequestWithKeyFormat:identify' + stage,
        () => identifyToken(tokenMedia(finalId), reader, flow.readReaders),
        {...params, reader},
    );
    if (isSameToken(secondToken, token) && secondToken.keyFormat === keyFormat) {
        return;
    }

    const reason = 'Итоговый контейнер создан на другом токене или в другом формате.';
    flow.logError('createRequestWithKeyFormat:verify' + stage, reason, {
        ...params,
        secondSerial: secondToken?.serialNumber,
        secondFamily: secondToken?.family,
        secondFormat: secondToken?.keyFormat,
    });
    await deleteQuietly(flow, finalId);
    throw new Error(reason);
}

/**
 * Перевыпуск с определением формата ключа по серийному номеру токена.
 *
 * 1. Для единственного заранее определённого Рутокена возможна прямая генерация.
 * 2. Для CSP и других носителей сразу возвращаем первый CSR. Для PKCS11 проверяем формат через API.
 * 3. Иной формат — второй контейнер на том же токене, затем удаляется первый.
 * 4. Второй контейнер создать не удалось — тоже остаётся первый CSR, ошибка в лог.
 *    Исключение — отмена пользователем: первый контейнер удаляется, ошибка пробрасывается.
 */
export async function createRequestWithKeyFormat(flow, name) {
    const direct = await prepareDirectRequest(flow);
    if (direct?.target) {
        const {token, keyFormat, target} = direct;
        const finalRequest = await flow.createRequest(name, {keyFormat, ...target});
        await verifyFinalRequest(flow, finalRequest, token, keyFormat);
        return {payload: finalRequest.payload, regenerated: false, direct: true};
    }

    const first = await flow.createRequest(name);
    // Ошибка идентификации или непригодный режим: контейнер уже создан — убираем его.
    const token = await withCleanupOnError(
        flow,
        first.containerId,
        'createRequestWithKeyFormat:identifyFirst',
        () => identifyToken(tokenMedia(first.containerId), first.reader, flow.readReaders),
        {reader: first.reader, media: tokenMedia(first.containerId)},
    );

    if (!token || token.keyFormat === KeyFormat.Csp) {
        return {payload: first.payload, regenerated: false};
    }

    const keyFormat = await withCleanupOnError(
        flow,
        first.containerId,
        'createRequestWithKeyFormat:resolveKeyFormat',
        () => resolveKeyFormat(flow, token, Boolean(direct && isSameToken(token, direct.token))),
        tokenParams(token),
    );

    if (!keyFormat || keyFormat === token.keyFormat) {
        return {payload: first.payload, regenerated: false};
    }

    flow.logError(
        'createRequestWithKeyFormat:secondContainer',
        'Формат ключа по серийному номеру отличается: ' +
            token.keyFormat +
            ' → ' +
            keyFormat,
        {...tokenParams(token), keyFormat},
    );

    const second = await createSecondRequest(
        flow,
        name,
        first.containerId,
        token,
        keyFormat,
    );

    // Второй контейнер создать не удалось — в заявку идёт CSR первого.
    if (!second) return {payload: first.payload, regenerated: false};

    await verifyFinalRequest(flow, second, token, keyFormat, first.containerId);

    try {
        await flow.deleteContainer(first.containerId);
    } catch (error) {
        flow.logError('createRequestWithKeyFormat:deleteFirst', error, {
            ...tokenParams(token),
            keyFormat,
            containerId: first.containerId,
        });

        throw new Error(
            'Итоговый контейнер создан, но удалить первоначальный не удалось. ' +
                (error instanceof Error ? error.message : String(error)),
        );
    }

    return {payload: second.payload, regenerated: true};
}

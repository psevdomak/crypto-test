import {KeyFormat} from './key-format.mjs';
import {
    findTargetReader,
    identifyToken,
    isSameToken,
    tokenMedia,
} from './token-identity.mjs';

/**
 * Интерфейс зависимостей совпадает с KeyFormatFlow
 * из sme-qds-ui (`libs/common/crypto/src/lib/cadescom/key-format-flow.ts`).
 *
 * createRequest(name, target?) отвечает `{payload, containerId, reader}`;
 * `target` — считыватель выбранного токена и режим ключа.
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
 * Формат, в котором нужно создавать итоговый ключ. `undefined` — остаётся первый
 * контейнер (API недоступен, вернул ошибку или неизвестный формат).
 */
async function resolveKeyFormat(flow, token) {
    if (!isSupportedFormat(token.keyFormat)) {
        throw new Error(
            'КриптоПро создал контейнер в режиме ' +
                token.keyFormat +
                '. Для перевыпуска подходят CSP и PKCS11.',
        );
    }

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
async function verifySecondRequest(flow, first, second, token, keyFormat) {
    const firstId = first.containerId;
    const {containerId: secondId, reader} = second;
    const params = {...tokenParams(token), keyFormat, firstId, secondId};

    if (!secondId?.trim()) {
        const reason = 'КриптоПро не вернул уникальное имя итогового контейнера.';
        flow.logError(
            'createRequestWithKeyFormat:emptySecondId',
            reason,
            params,
        );

        throw new Error(reason + ' Формат не подтверждён.');
    }

    if (secondId === firstId) {
        const reason = 'КриптоПро вернул тот же контейнер при второй генерации.';
        flow.logError('createRequestWithKeyFormat:verifySecond', reason, params);
        throw new Error(reason);
    }

    const secondToken = await withCleanupOnError(
        flow,
        secondId,
        'createRequestWithKeyFormat:identifySecond',
        () => identifyToken(tokenMedia(secondId), reader, flow.readReaders),
        {...params, reader},
    );
    if (isSameToken(secondToken, token) && secondToken.keyFormat === keyFormat) {
        return;
    }

    const reason = 'Итоговый контейнер создан на другом токене или в другом формате.';
    flow.logError('createRequestWithKeyFormat:verifySecond', reason, {
        ...params,
        secondSerial: secondToken?.serialNumber,
        secondFamily: secondToken?.family,
        secondFormat: secondToken?.keyFormat,
    });
    await deleteQuietly(flow, secondId);
    throw new Error(reason);
}

/**
 * Перевыпуск с определением формата ключа по серийному номеру токена.
 *
 * 1. Первая генерация — как раньше.
 * 2. Не Рутокен, ошибка API, неизвестный или тот же формат — остаётся первый CSR.
 * 3. Иной формат — второй контейнер на том же токене, затем удаляется первый.
 * 4. Второй контейнер создать не удалось — тоже остаётся первый CSR, ошибка в лог.
 *    Исключение — отмена пользователем: первый контейнер удаляется, ошибка пробрасывается.
 */
export async function createRequestWithKeyFormat(flow, name) {
    const first = await flow.createRequest(name);
    // Ошибка идентификации или непригодный режим: контейнер уже создан — убираем его.
    const token = await withCleanupOnError(
        flow,
        first.containerId,
        'createRequestWithKeyFormat:identifyFirst',
        () => identifyToken(tokenMedia(first.containerId), first.reader, flow.readReaders),
        {reader: first.reader, media: tokenMedia(first.containerId)},
    );

    if (!token) return {payload: first.payload, regenerated: false};

    const keyFormat = await withCleanupOnError(
        flow,
        first.containerId,
        'createRequestWithKeyFormat:resolveKeyFormat',
        () => resolveKeyFormat(flow, token),
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

    await verifySecondRequest(flow, first, second, token, keyFormat);

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

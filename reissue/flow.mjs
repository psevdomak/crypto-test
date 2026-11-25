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

/** Второй контейнер на том же токене в запрошенном API формате. */
async function createSecondRequest(flow, name, firstId, token, keyFormat) {
    const params = {...tokenParams(token), keyFormat};
    let target;
    try {
        target = findTargetReader(await flow.readReaders(), token, keyFormat);
    } catch (error) {
        flow.logError('createRequestWithKeyFormat:findTargetReader', error, {
            ...params,
            containerId: firstId,
        });
        throw error;
    }

    return withCleanupOnError(
        flow,
        firstId,
        'createRequestWithKeyFormat:createSecond',
        () => flow.createRequest(name, {keyFormat, ...target}),
        params,
    );
}

/** Итоговый контейнер должен быть на том же токене и в нужном формате; иначе он удаляется. */
async function verifySecondRequest(flow, first, second, token, keyFormat) {
    if (!second.containerId?.trim()) {
        throw new Error('КриптоПро не вернул уникальное имя итогового контейнера. Формат не подтверждён.');
    }

    const isSameContainer = second.containerId === first.containerId;
    const identify = () =>
        identifyToken(tokenMedia(second.containerId), second.reader, flow.readReaders);
    // Тот же контейнер удалять нельзя: он остался бы единственным.
    const secondToken = isSameContainer
        ? await identify()
        : await withCleanupOnError(
              flow,
              second.containerId,
              'createRequestWithKeyFormat:identifySecond',
              identify,
              {...tokenParams(token), keyFormat, reader: second.reader},
          );

    if (
        !isSameContainer &&
        isSameToken(secondToken, token) &&
        secondToken?.keyFormat === keyFormat
    ) {
        return;
    }

    flow.logError(
        'createRequestWithKeyFormat:verifySecond',
        isSameContainer
            ? 'Вторая генерация вернула тот же контейнер, формат не изменён'
            : 'Итоговый контейнер создан на другом токене или в другом формате',
        {
            ...tokenParams(token),
            keyFormat,
            firstId: first.containerId,
            secondId: second.containerId,
            secondSerial: secondToken?.serialNumber,
            secondFamily: secondToken?.family,
            secondFormat: secondToken?.keyFormat,
        },
    );

    if (!isSameContainer) await deleteQuietly(flow, second.containerId);

    throw new Error('Итоговый контейнер создан на другом токене или в другом формате.');
}

/**
 * Перевыпуск с определением формата ключа по серийному номеру токена.
 *
 * 1. Первая генерация — как раньше.
 * 2. Не Рутокен, ошибка API, неизвестный или тот же формат — остаётся первый CSR.
 * 3. Иной формат — второй контейнер на том же токене, затем удаляется первый.
 * 4. Ошибка или отмена при создании второго контейнера — убрать первый и вернуть ошибку.
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

    if (!token) return first.payload;

    const keyFormat = await withCleanupOnError(
        flow,
        first.containerId,
        'createRequestWithKeyFormat:resolveKeyFormat',
        () => resolveKeyFormat(flow, token),
        tokenParams(token),
    );

    if (!keyFormat || keyFormat === token.keyFormat) return first.payload;

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
        name + '-final',
        first.containerId,
        token,
        keyFormat,
    );

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

    return second.payload;
}

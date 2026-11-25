import { createRequestWithKeyFormat } from './flow.mjs?v=25';
import { cryptoProAdapter } from './cryptopro.mjs?v=21';

const SUBJECT = 'CN=CryptoPro reissue test';
const element = (id) => document.getElementById(id);
const form = element('setup');
const cleanup = element('cleanup');
const log = element('log');
let adapter;

function report(message, details) {
    const text = typeof details === 'string' ? details : JSON.stringify(details, null, 2);
    const entry = text === undefined ? message : message + '\n' + text;
    log.prepend(document.createTextNode(entry + '\n\n'));
}

async function perform(operation) {
    const controls = form.querySelectorAll('fieldset, button[type="submit"]');
    controls.forEach((control) => { control.disabled = true; });
    try {
        if (!adapter) {
            const plugin = window.cadesplugin;
            if (!plugin) throw new Error('Скрипт КриптоПро не загрузился.');
            await plugin;
            adapter = cryptoProAdapter(plugin, report);
            try {
                report('Версии КриптоПро', await adapter.versions());
            } catch (error) {
                report('Версии КриптоПро недоступны', error.message || String(error));
            }
        }
        await operation();
    } catch (error) {
        report('Ошибка', error.message || String(error));
    } finally {
        cleanup.disabled = !adapter?.owned().length;
        controls.forEach((control) => { control.disabled = false; });
    }
}

// Мок `POST /api/v1/company/{companyId}/common/key-format`: бэкенд возвращает
// result.keyFormat либо ошибается. Неизвестное значение отдаётся как есть —
// сценарий сам решает оставить первый CSR.
function mockKeyFormat(value) {
    return async (serialNumber) => {
        report('Мок POST key-format', { serialNumber });
        if (value === 'error') throw new Error('Мок API вернул HTTP 503');

        return value;
    };
}

element('readers').addEventListener('click', () => perform(async () => {
    const readers = await adapter.readers();
    report('Режимы считывателей (' + readers.length + ')', readers);
}));

form.addEventListener('submit', (event) => {
    event.preventDefault();
    return perform(async () => {
        const mock = element('mock').value;
        const name = 'reissue-' + crypto.randomUUID();
        report('Запуск прогона', { name, mockFormat: mock });

        const { payload, regenerated } = await createRequestWithKeyFormat(
            {
                createRequest: (requestName, target) =>
                    adapter.generate(requestName, SUBJECT, target),
                readReaders: () => adapter.readers(),
                deleteContainer: (containerId) => adapter.remove(containerId),
                requestKeyFormat: mockKeyFormat(mock),
                logError: (method, error, params) => {
                    report(method, {
                        error: error?.message || String(error),
                        ...params,
                    });
                },
            },
            name,
        );

        const outcome = regenerated
            ? 'Итоговый CSR создан, первоначальный контейнер удалён.'
            : 'Сохранён первый CSR.';
        report(outcome, 'CSR\n' + payload.certificateRequest);
    });
});

cleanup.addEventListener('click', () => perform(async () => {
    for (const containerId of adapter.owned()) {
        await adapter.remove(containerId);
    }
    report('Тестовые контейнеры удалены.');
}));

import { cryptoProAdapter } from './cryptopro.mjs?v=3';
import { reissue } from './flow.mjs?v=3';

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
    const controls = form.querySelectorAll('fieldset');
    controls.forEach((fieldset) => { fieldset.disabled = true; });
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
        controls.forEach((fieldset) => { fieldset.disabled = false; });
    }
}

element('readers').addEventListener('click', () => perform(async () => {
    const readers = await adapter.readers();
    report('Режимы считывателей (' + readers.length + ')', readers);
}));

form.addEventListener('submit', (event) => {
    event.preventDefault();
    return perform(async () => {
        const mockFormat = element('mock').value;
        const name = 'reissue-' + crypto.randomUUID();
        report('Запуск прогона', { name, mockFormat });
        const result = await reissue({ adapter, mockFormat, name, report });
        const serial = 'Серийный номер Рутокена: ' + result.serialNumber + '. ';
        const outcome = result.regenerated
            ? 'Итоговый CSR создан, первоначальный контейнер удалён. Сверьте режим ключа и число нативных диалогов.'
            : 'Сохранён первый CSR. Проверьте режим ключа на токене.';
        report(serial + outcome, 'CSR\n' + result.csr);
    });
});

cleanup.addEventListener('click', () => perform(async () => {
    for (const container of adapter.owned()) {
        await adapter.remove(container);
    }
    report('Тестовые контейнеры удалены.');
}));

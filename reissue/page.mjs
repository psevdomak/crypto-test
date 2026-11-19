import { cryptoProAdapter } from './cryptopro.mjs';
import { reissue } from './flow.mjs';

const element = (id) => document.getElementById(id);
const form = element('setup');
const status = element('status');
const cleanup = element('cleanup');
const log = element('log');
let adapter;

function report(message, details) {
    const entry = message + (details === undefined ? '' : '\n' + JSON.stringify(details, null, 2));
    log.prepend(document.createTextNode(entry + '\n\n'));
}

async function perform(operation) {
    const controls = form.querySelectorAll('fieldset');
    controls.forEach((fieldset) => { fieldset.disabled = true; });
    status.textContent = 'Выполняется…';
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
        status.textContent = await operation();
    } catch (error) {
        const message = error.message || String(error);
        report('Ошибка', message);
        status.textContent = message;
    } finally {
        cleanup.disabled = !adapter?.owned().length;
        controls.forEach((fieldset) => { fieldset.disabled = false; });
    }
}

element('readers').addEventListener('click', () => perform(async () => {
    const readers = await adapter.readers();
    report('Режимы считывателей', readers);
    return 'Режимов считывателей: ' + readers.length;
}));

form.addEventListener('submit', (event) => {
    event.preventDefault();
    element('result').hidden = true;
    element('csr').value = '';
    perform(async () => {
        const mockFormat = element('mock').value;
        const subject = element('subject').value.trim();
        if (!subject) throw new Error('Укажите субъект CSR.');
        const name = 'reissue-' + crypto.randomUUID();
        report('Запуск прогона', { name, mockFormat });
        const result = await reissue({ adapter, mockFormat, name, subject, report });
        element('csr').value = result.csr;
        element('result').hidden = false;
        const serial = 'Серийный номер Рутокена: ' + result.serialNumber + '. ';
        return serial + (result.regenerated
            ? 'CSR создан повторно. Сверьте режим ключа на токене и число нативных диалогов.'
            : 'Сохранён первый CSR. Проверьте режим ключа на токене.');
    });
});

cleanup.addEventListener('click', () => perform(async () => {
    element('result').hidden = true;
    element('csr').value = '';
    for (const container of adapter.owned()) {
        await adapter.remove(container);
    }
    return 'Тестовые контейнеры удалены.';
}));
